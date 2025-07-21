package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"simple_kerberos/internal/dto"
	"simple_kerberos/internal/messages"
	"simple_kerberos/internal/network"
	"simple_kerberos/internal/security"
)

func StartService(serverIp string, serverPort int, serviceId string, key []byte) {
	serverAddr := net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP(serverIp),
	}

	startService(serverAddr, serviceId, key)
}

func startService(serverAddr net.UDPAddr, serviceId string, key []byte) {
	fmt.Println("Service " + serviceId + " listening on " + serverAddr.IP.String() + ":" + fmt.Sprint(serverAddr.Port) + "...")
	network.ListenUDP(serverAddr, 1024, func(b []byte, u *net.UDPAddr) ([]byte, error) {
		return serviceRequestHandler(b, u, serviceId, key)
	}, serviceErrorHandler)

}

func serviceRequestHandler(data []byte, clientAddr *net.UDPAddr, serviceId string, tgsKey []byte) ([]byte, error) {

	var req messages.ServiceRequest
	json.Unmarshal(data, &req)

	fmt.Println("[" + serviceId + "]: recieved request")

	reply, err := serviceBuildReply(req, clientAddr, serviceId, tgsKey)
	if err != nil {
		fmt.Println("["+serviceId+"] Server Error: ", err)
	}

	replyJson, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}

	return replyJson, nil
}

func serviceBuildReply(req messages.ServiceRequest, clientAddr *net.UDPAddr, serviceId string, asKey []byte) (messages.Reply, error) {

	//CHECK MAC AND DECRYPT TICKET
	mac := security.MacData(req.EncryptedTicket, asKey)
	if !bytes.Equal(mac, req.EncTicketMac) {
		return errorReply("["+serviceId+"] ERROR: mac check for recieved ticket failed", true), nil
	}

	ticketJson, err := security.SymmetricDecryption(req.EncryptedTicket, asKey)
	var ticket dto.Ticket
	json.Unmarshal(ticketJson, &ticket)
	if err != nil {
		return errorReply("["+serviceId+"] ERROR: inconsistent message recieved", true), nil
	}

	if ticket.TargetId != serviceId {
		return errorReply("["+serviceId+"] ERROR: wrong serviceId", true), nil
	}

	//CHECK MAC AND DECRYPT AUTHENTICATOR
	mac = security.MacData(req.EncryptedAuthenticator, ticket.Key)
	if !bytes.Equal(mac, req.EncAuthenticatorMac) {
		return errorReply("["+serviceId+"] ERROR: mac check for recieved authenticator failed", true), nil
	}

	authenticatorJson, err := security.SymmetricDecryption(req.EncryptedAuthenticator, ticket.Key)
	var authenticator dto.Authenticator
	json.Unmarshal(authenticatorJson, &authenticator)
	if err != nil {
		return errorReply("["+serviceId+"] ERROR: inconsistent authenticator recieved", true), nil
	}

	//CHECK AUTHENTICATOR
	check, reason := checkTicketValidity(authenticator, ticket, clientAddr)
	if !check {
		return errorReply("["+serviceId+"] "+reason, true), nil
	}

	//CREATE RESPONSE TIMESTAMP
	serviceReply := messages.ServiceReply{
		Timestamp: authenticator.Timestamp + 1,
	}

	serviceReplyJson, err := json.Marshal(serviceReply)
	if err != nil {
		return errorReply("["+serviceId+"] ERROR: Generic server error", false), err
	}

	encryptedServiceReply, err := security.SymmetricEncryption(serviceReplyJson, ticket.Key)
	if err != nil {
		return errorReply("["+serviceId+"] ERROR: Generic server error", false), err
	}

	reply := messages.Reply{
		IsError:       false,
		Message:       "Hello " + ticket.ClientId + ": Authenticated",
		EncryptedData: encryptedServiceReply,
		EncDataMac:    security.MacData(encryptedServiceReply, ticket.Key),
	}

	fmt.Println("[" + serviceId + "]: OK " + ticket.ClientId + " authenticated")
	return reply, nil
}

func serviceErrorHandler(err error) {
	fmt.Println("Error recieving UDP packet")
}
