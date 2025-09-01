package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	config "simple_kerberos/configs"
	"simple_kerberos/internal/dao"
	"simple_kerberos/internal/dto"
	"simple_kerberos/internal/messages"
	"simple_kerberos/internal/network"
	"simple_kerberos/internal/security"
	"time"
)

func StartTGS(serverIp string, tgsId string, key []byte, adminPwd string) {
	serverAddr := net.UDPAddr{
		Port: config.TgsPort,
		IP:   net.ParseIP(serverIp),
	}

	startTGS(serverAddr, tgsId, key, adminPwd)
}

func StartTGSDefaultIp(tgsId string, key []byte, adminPwd string) {
	serverAddr := net.UDPAddr{
		Port: config.TgsPort,
	}

	startTGS(serverAddr, tgsId, key, adminPwd)
}

func startTGS(serverAddr net.UDPAddr, tgsId string, key []byte, adminPwd string) {
	fmt.Println("Kerberos TGS " + tgsId + " listening on " + serverAddr.IP.String() + ":" + fmt.Sprint(serverAddr.Port) + "...")
	network.ListenUDP(serverAddr, 1024, func(b []byte, u *net.UDPAddr) ([]byte, error) {
		return tgsRequestHandler(b, u, tgsId, key, adminPwd)
	}, tgsErrorHandler)

}

func tgsRequestHandler(data []byte, clientAddr *net.UDPAddr, tgsId string, asKey []byte, adminPwd string) ([]byte, error) {

	var req messages.TGSRequest
	json.Unmarshal(data, &req)

	fmt.Println("[TGS]: recieved request for " + req.ServiceId)

	reply, err := tgsBuildReply(req, clientAddr, tgsId, asKey, adminPwd)
	if err != nil {
		fmt.Println("[TGS] Server Error: ", err)
	}

	replyJson, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}

	return replyJson, nil
}

func tgsBuildReply(req messages.TGSRequest, clientAddr *net.UDPAddr, tgsId string, asKey []byte, adminPwd string) (messages.Reply, error) {

	//CHECK MAC AND DECRYPT TICKET
	mac := security.MacData(req.EncryptedTicket, asKey)
	if !bytes.Equal(mac, req.EncTicketMac) {
		return errorReply("[TGS] ERROR: mac check for recieved ticket for service "+req.ServiceId+" failed", true), nil
	}

	tgsTicketJson, err := security.SymmetricDecryption(req.EncryptedTicket, asKey)
	var tgsTicket dto.Ticket
	json.Unmarshal(tgsTicketJson, &tgsTicket)
	if err != nil {
		return errorReply("[TGS] ERROR: inconsistent message recieved", true), nil
	}

	if tgsTicket.TargetId != tgsId {
		return errorReply("[TGS] ERROR: wrong tsgId", true), nil
	}

	//CHECK MAC AND DECRYPT AUTHENTICATOR
	mac = security.MacData(req.EncryptedAuthenticator, tgsTicket.Key)
	if !bytes.Equal(mac, req.EncAuthenticatorMac) {
		return errorReply("[TGS] ERROR: mac check for recieved authenticator for service "+req.ServiceId+" failed", true), nil
	}

	authenticatorJson, err := security.SymmetricDecryption(req.EncryptedAuthenticator, tgsTicket.Key)
	var authenticator dto.Authenticator
	json.Unmarshal(authenticatorJson, &authenticator)
	if err != nil {
		return errorReply("[TGS] ERROR: inconsistent authenticator recieved", true), nil
	}

	//CHECK AUTHENTICATOR
	check, reason := checkTicketValidity(authenticator, tgsTicket, clientAddr)
	if !check {
		return errorReply("[TGS] "+reason, true), nil
	}

	//OPEN DB
	db, err := dao.OpenEncryptedTGSDb(config.TgsDbPath+tgsId+".db", adminPwd)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}
	defer db.Close()

	//RETRIVE SERVICE
	exists, err := dao.ServiceExists(req.ServiceId, db)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}
	if !exists {
		return errorReply("[TGS] ERROR: unknown "+req.ServiceId+" or other problems", true), nil
	}

	service, err := dao.GetServiceByServiceId(req.ServiceId, db)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	//CREATE TICKET
	timestamp := time.Now().UnixMilli()
	keyClientService := security.GenerateRandomKey(config.SymmKeyDim)

	serviceTicket := dto.Ticket{
		Key:           keyClientService,
		ClientId:      tgsTicket.ClientId,
		ClientAddress: tgsTicket.ClientAddress,
		TargetId:      req.ServiceId,
		Timestamp:     timestamp,
		Lifetime:      config.Lifetime,
	}

	//ENCRYPT TICKET
	jsonServiceTicket, err := json.Marshal(serviceTicket)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	encryptedServiceTicket, err := security.SymmetricEncryption(jsonServiceTicket, service.Key)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	//CREATE TICKET DATA
	ticketData := dto.TicketData{
		Key:             keyClientService,
		TargetId:        req.ServiceId,
		Timestamp:       timestamp,
		Lifetime:        config.Lifetime,
		EncryptedTicket: encryptedServiceTicket,
		EncTicketMac:    security.MacData(encryptedServiceTicket, service.Key),
	}

	//ENCRYPT TICKET DATA
	jsonTicketData, err := json.Marshal(ticketData)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}
	encryptedTicketData, err := security.SymmetricEncryption(jsonTicketData, tgsTicket.Key)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	reply := messages.Reply{
		IsError:       false,
		Message:       "OK",
		EncryptedData: encryptedTicketData,
		EncDataMac:    security.MacData(encryptedTicketData, tgsTicket.Key),
	}

	fmt.Println("[TGS]: OK " + tgsTicket.ClientId + " -> " + req.ServiceId)
	return reply, nil
}

func tgsErrorHandler(err error) {
	fmt.Println("Error recieving UDP packet")
}

func checkTicketValidity(authenticator dto.Authenticator, ticket dto.Ticket, clientAddr *net.UDPAddr) (bool, string) {

	if authenticator.Timestamp > time.Now().UnixMilli() {
		return false, "Error: invalid authenticator, it's coming from the future?!"
	}

	if time.Now().UnixMilli()-authenticator.Timestamp > config.AuthenticatorFreshnessTime {
		return false, "Error: invalid authenticator, too old"
	}

	if time.Now().UnixMilli() > ticket.Timestamp+ticket.Lifetime {
		return false, "Error: ticket expired"
	}

	if authenticator.ClientId != ticket.ClientId {
		return false, "Error: wrong clientId"
	}

	if authenticator.ClientAddress != ticket.ClientAddress {
		return false, "Error: wrong declared clientAddress"
	}

	if clientAddr.IP.String() != ticket.ClientAddress {
		return false, "Error: request recieved from a wrong address"
	}

	return true, ""
}
