package protocol

import (
	"bytes"
	"encoding/json"
	"net"
	config "simple_kerberos/configs"
	"simple_kerberos/internal/dao"
	"simple_kerberos/internal/dto"
	"simple_kerberos/internal/kerrors"
	"simple_kerberos/internal/messages"
	"simple_kerberos/internal/network"
	"simple_kerberos/internal/security"
	"time"
)

func RequestToAs(serverIp string, req messages.ASRequest, clientPwd string) (dto.TicketData, error) {

	clientKey, err := security.GenerateClientKeyFromPwd(clientPwd, config.SymmKeyDim)
	if err != nil {
		return dto.TicketData{}, err
	}

	//MARSHAL REQ
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return dto.TicketData{}, err
	}

	//SEND REQUEST WAITING FOR REPLY
	jsonReply, err := sendRequest(serverIp, config.AsPort, jsonReq)
	if err != nil {
		return dto.TicketData{}, err
	}

	//UNMARSHAL REPLY
	var reply messages.Reply
	err = json.Unmarshal(jsonReply, &reply)
	if err != nil {
		return dto.TicketData{}, err
	}

	if reply.IsError {
		return dto.TicketData{}, &kerrors.ReplyError{Msg: reply.Message}
	}

	//CHECK INTEGRITY
	mac := security.MacData(reply.EncryptedData, clientKey)
	if !bytes.Equal(mac, reply.EncDataMac) {
		return dto.TicketData{}, &kerrors.ReplyError{Msg: "ERROR: Recieved hmac does not match with computed hmac. Data has been modified or wrong password provided"}
	}

	//DECRYPT AND PARSE TICKET DATA
	jsonTicketData, err := security.SymmetricDecryption(reply.EncryptedData, clientKey)
	if err != nil {
		return dto.TicketData{}, err
	}

	var ticketData dto.TicketData
	err = json.Unmarshal(jsonTicketData, &ticketData)

	if err != nil {
		return dto.TicketData{}, &kerrors.PasswordError{Msg: "Wrong password"}
	}
	return ticketData, nil
}

func SaveTGSTicket(clientId string, data dto.TicketData) error {
	db, err := dao.OpenDb(config.ClientDbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	exists, err := dao.TGSTicketExists(clientId, data.TargetId, db)
	if err != nil {
		return err
	}

	if exists {
		return dao.UpdateTGSTicket(clientId, data, db)
	} else {
		return dao.InsertTGSTicket(clientId, data, db)
	}

}

func RetriveTGSTicket(clientId string, tgsId string) (dto.TicketData, error) {
	db, err := dao.OpenDb(config.ClientDbPath)
	if err != nil {
		return dto.TicketData{}, err
	}
	defer db.Close()

	exists, err := dao.TGSTicketExists(clientId, tgsId, db)
	if err != nil {
		return dto.TicketData{}, err
	}

	if !exists {
		return dto.TicketData{}, &kerrors.TokenError{Msg: "ERROR: No ticket found for " + clientId + " and TGS " + tgsId + ". Authentication with AS needed"}
	}

	ticketData, err := dao.GetTGSTicket(clientId, tgsId, db)

	if err != nil {
		return dto.TicketData{}, err
	}

	if ticketData.Timestamp > time.Now().UnixMilli()+ticketData.Lifetime {
		dao.DeleteTGSTicket(clientId, tgsId, db)
		return dto.TicketData{}, &kerrors.TokenError{Msg: "ERROR: Ticket for " + clientId + " and TGS " + tgsId + " is expired. Old ticket deleted. Authentication with AS needed"}
	}

	return ticketData, nil

}

func RetriveServiceTicket(clientId string, serviceId string) (dto.TicketData, error) {
	db, err := dao.OpenDb(config.ClientDbPath)
	if err != nil {
		return dto.TicketData{}, err
	}
	defer db.Close()

	exists, err := dao.ServiceTicketExists(clientId, serviceId, db)
	if err != nil {
		return dto.TicketData{}, err
	}

	if !exists {
		return dto.TicketData{}, &kerrors.TokenError{Msg: "ERROR: No ticket found for " + clientId + " and service " + serviceId + ". Authentication with TGS needed"}
	}

	ticketData, err := dao.GetServiceTicket(clientId, serviceId, db)

	if err != nil {
		return dto.TicketData{}, err
	}

	if ticketData.Timestamp > time.Now().UnixMilli()+ticketData.Lifetime {
		dao.DeleteServiceTicket(clientId, serviceId, db)
		return dto.TicketData{}, &kerrors.TokenError{Msg: "ERROR: Ticket for " + clientId + " and service " + serviceId + " is expired. Old ticket deleted. Authentication with TGS needed"}
	}

	return ticketData, nil

}

func PrepareTGSRequest(serverIp string, clientId string, serviceId string, ticketData dto.TicketData) (messages.TGSRequest, error) {

	_, encryptedAuth, err := prepareEncryptedAuthenticator(serverIp, clientId, ticketData.Key)
	if err != nil {
		return messages.TGSRequest{}, err
	}

	req := messages.TGSRequest{
		ServiceId:              serviceId,
		EncryptedTicket:        ticketData.EncryptedTicket,
		EncTicketMac:           ticketData.EncTicketMac,
		EncryptedAuthenticator: encryptedAuth,
		EncAuthenticatorMac:    security.MacData(encryptedAuth, ticketData.Key),
	}

	return req, nil
}

func PrepareServiceRequest(serverIp string, clientId string, serviceId string, ticketData dto.TicketData) (messages.ServiceRequest, int64, error) {

	auth, encryptedAuth, err := prepareEncryptedAuthenticator(serverIp, clientId, ticketData.Key)
	if err != nil {
		return messages.ServiceRequest{}, -1, err
	}

	req := messages.ServiceRequest{
		EncryptedTicket:        ticketData.EncryptedTicket,
		EncTicketMac:           ticketData.EncTicketMac,
		EncryptedAuthenticator: encryptedAuth,
		EncAuthenticatorMac:    security.MacData(encryptedAuth, ticketData.Key),
	}

	return req, auth.Timestamp, nil
}

func RequestToTgs(serverIp string, req messages.TGSRequest, tgsTicketData dto.TicketData) (dto.TicketData, error) {

	//MARSHAL REQ
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return dto.TicketData{}, err
	}

	//SEND REQUEST WAITING FOR REPLY
	jsonReply, err := sendRequest(serverIp, config.TgsPort, jsonReq)
	if err != nil {
		return dto.TicketData{}, err
	}

	//UNMARSHAL REPLY
	var reply messages.Reply
	err = json.Unmarshal(jsonReply, &reply)
	if err != nil {
		return dto.TicketData{}, err
	}

	if reply.IsError {
		return dto.TicketData{}, &kerrors.ReplyError{Msg: reply.Message}
	}

	//CHECK INTEGRITY
	mac := security.MacData(reply.EncryptedData, tgsTicketData.Key)
	if !bytes.Equal(mac, reply.EncDataMac) {
		return dto.TicketData{}, &kerrors.ReplyError{Msg: "ERROR: Recieved hmac does not match with computed hmac. Data has been modified or wrong password provided"}
	}

	//DECRYPT AND PARSE TICKET DATA
	jsonTicketData, err := security.SymmetricDecryption(reply.EncryptedData, tgsTicketData.Key)
	if err != nil {
		return dto.TicketData{}, err
	}

	var serviceTicketData dto.TicketData
	err = json.Unmarshal(jsonTicketData, &serviceTicketData)

	if err != nil {
		return dto.TicketData{}, &kerrors.PasswordError{Msg: "Wrong key used to decrypt"}
	}
	return serviceTicketData, nil
}

func RequestToService(serverIp string, serverPort int, req messages.ServiceRequest, serviceTicketData dto.TicketData, currentTimestamp int64) (string, error) {

	//MARSHAL REQ
	jsonReq, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	//SEND REQUEST WAITING FOR REPLY
	jsonReply, err := sendRequest(serverIp, serverPort, jsonReq)
	if err != nil {
		return "", err
	}

	//UNMARSHAL REPLY
	var reply messages.Reply
	err = json.Unmarshal(jsonReply, &reply)
	if err != nil {
		return "", err
	}

	if reply.IsError {
		return "", &kerrors.ReplyError{Msg: reply.Message}
	}

	//CHECK INTEGRITY
	mac := security.MacData(reply.EncryptedData, serviceTicketData.Key)
	if !bytes.Equal(mac, reply.EncDataMac) {
		return "", &kerrors.ReplyError{Msg: "ERROR: Recieved hmac does not match with computed hmac. Data has been modified or wrong key used"}
	}

	//DECRYPT AND PARSE TICKET DATA
	jsonServiceReply, err := security.SymmetricDecryption(reply.EncryptedData, serviceTicketData.Key)
	if err != nil {
		return "", err
	}

	var serviceReply messages.ServiceReply
	err = json.Unmarshal(jsonServiceReply, &serviceReply)
	if err != nil {
		return "", &kerrors.PasswordError{Msg: "Wrong key used to decrypt"}
	}
	if currentTimestamp != serviceReply.Timestamp-1 {
		return "", &kerrors.ReplyError{Msg: "ERROR: Got incorrect timestamp from the server, reply discarded"}
	}

	return reply.Message, nil
}

func sendRequest(serverIp string, serverPort int, jsonReq []byte) ([]byte, error) {

	serverAddr := net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP(serverIp),
	}

	localIp, err := network.GetActiveIP(serverIp)
	if err != nil {
		return []byte{}, err
	}

	localAddr := net.UDPAddr{
		Port: 0,
		IP:   localIp,
	}

	//SEND REQUEST WAITING FOR REPLY
	return network.SendUDPRequest(&localAddr, &serverAddr, jsonReq, 1024)
}

func SaveServiceTicket(clientId string, data dto.TicketData) error {
	db, err := dao.OpenDb(config.ClientDbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	exists, err := dao.ServiceTicketExists(clientId, data.TargetId, db)
	if err != nil {
		return err
	}

	if exists {
		return dao.UpdateServiceTicket(clientId, data, db)
	} else {
		return dao.InsertServiceTicket(clientId, data, db)
	}

}

func prepareEncryptedAuthenticator(serverIp string, clientId string, encryptionKey []byte) (dto.Authenticator, []byte, error) {
	localIp, err := network.GetActiveIP(serverIp)
	if err != nil {
		return dto.Authenticator{}, nil, err
	}

	auth := dto.Authenticator{
		ClientId:      clientId,
		ClientAddress: localIp.String(),
		Timestamp:     time.Now().UnixMilli(),
	}

	jsonAuth, err := json.Marshal(auth)
	if err != nil {
		return dto.Authenticator{}, nil, err
	}

	encAuth, err := security.SymmetricEncryption(jsonAuth, encryptionKey)
	if err != nil {
		return dto.Authenticator{}, nil, err
	}
	return auth, encAuth, nil
}
