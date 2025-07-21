package protocol

import (
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

func StartAS(serverIp string, adminPwd string) {
	serverAddr := net.UDPAddr{
		Port: config.AsPort,
		IP:   net.ParseIP(serverIp),
	}

	startAS(serverAddr, adminPwd)
}

func StartASDefaultIp(adminPwd string) {
	serverAddr := net.UDPAddr{
		Port: config.AsPort,
	}

	startAS(serverAddr, adminPwd)
}

func startAS(serverAddr net.UDPAddr, adminPwd string) {
	fmt.Println("Kerberos AS listening on " + serverAddr.IP.String() + ":" + fmt.Sprint(serverAddr.Port) + "...")
	network.ListenUDP(serverAddr, 1024, func(b []byte, a *net.UDPAddr) ([]byte, error) {
		return asRequestHandler(b, a, adminPwd)
	}, asErrorHandler)

}

func asRequestHandler(data []byte, clientAddr *net.UDPAddr, adminPwd string) ([]byte, error) {
	var req messages.ASRequest
	json.Unmarshal(data, &req)
	fmt.Println("[AS]: recieved request from " + req.ClientId + " for " + req.TGSId)

	reply, err := asBuildReply(req, clientAddr, adminPwd)
	if err != nil {
		fmt.Println("[TGS] Server Error: ", err)
	}

	replyJson, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}

	return replyJson, nil
}

func asBuildReply(req messages.ASRequest, clientAddr *net.UDPAddr, adminPwd string) (messages.Reply, error) {

	db, err := dao.OpenEncryptedASDb(config.AsDbPath, adminPwd)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}
	defer db.Close()

	//RETRIVE CLIENT
	client, err := dao.GetClientByClientId(req.ClientId, db)
	if err != nil {
		return errorReply("[AS] ERROR: client "+req.ClientId+" not registered or other problems", true), nil
	}

	//RETRIVE TGS
	tgs, err := dao.GetTGSByTgsId(req.TGSId, db)
	if err != nil {
		return errorReply("[AS] ERROR: tgs "+req.TGSId+" not known or other problems", true), nil
	}

	//CREATE TOKEN
	timestamp := time.Now().UnixMilli()
	keyClientTGS := security.GenerateRandomKey(config.SymmKeyDim)

	ticket := dto.Ticket{
		Key:           keyClientTGS,
		ClientId:      req.ClientId,
		ClientAddress: clientAddr.IP.String(),
		TargetId:      req.TGSId,
		Timestamp:     timestamp,
		Lifetime:      config.Lifetime,
	}

	//ENCRYPT TOKEN
	jsonTicket, err := json.Marshal(ticket)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	encryptedTicket, err := security.SymmetricEncryption(jsonTicket, tgs.Key)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	//CREATE TICKET DATA
	ticketData := dto.TicketData{
		Key:             keyClientTGS,
		TargetId:        req.TGSId,
		Timestamp:       timestamp,
		Lifetime:        config.Lifetime,
		EncryptedTicket: encryptedTicket,
		EncTicketMac:    security.MacData(encryptedTicket, tgs.Key),
	}

	//ENCRYPT TICKET DATA
	jsonTicketData, err := json.Marshal(ticketData)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}
	encryptedTicketData, err := security.SymmetricEncryption(jsonTicketData, client.Key)
	if err != nil {
		return errorReply("[TGS] ERROR: Generic server error", false), err
	}

	reply := messages.Reply{
		IsError:       false,
		Message:       "OK",
		EncryptedData: encryptedTicketData,
		EncDataMac:    security.MacData(encryptedTicketData, client.Key),
	}

	fmt.Println("[AS]: OK " + req.ClientId + " -> " + req.TGSId)
	return reply, nil
}

func asErrorHandler(err error) {
	fmt.Println("[AS] [GENERIC ERROR]: ", err)
}

func AddTGS(tgsId string, key []byte, adminPwd string) error {

	db, err := dao.OpenEncryptedASDb(config.AsDbPath, adminPwd)
	if err != nil {
		return err
	}

	exists, err := dao.TgsExists(tgsId, db)
	if err != nil {
		return err
	}

	if exists {
		return dao.UpdateTgsKey(tgsId, key, db)
	} else {
		return dao.InsertTGS(tgsId, key, db)
	}

}
