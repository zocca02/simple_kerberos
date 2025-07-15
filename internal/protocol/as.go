package protocol

import (
	"encoding/json"
	"fmt"
	"net"
	"simple_kerberos/internal/messages"
	"simple_kerberos/internal/network"
	"simple_kerberos/internal/security"
	"time"
)

const lifetime int64 = 30 * 60 * 1000
const symmKeyDim int = 128

func StartAS() {
	serverAddr := net.UDPAddr{
		Port: 8888,
	}

	fmt.Println("Kerberos AS listening on port 8888...")
	network.ListenUDP(serverAddr, 1024, asRequestHandler, asErrorHandler)

}

func asRequestHandler(data []byte, clientAddr *net.UDPAddr) ([]byte, error) {
	var req messages.ASRequest
	json.Unmarshal(data, &req)

	timestamp := time.Now().UnixMilli()

	tgsKey := security.GenerateRandomKey(symmKeyDim) // DA CAMBIARE
	keyClientTGS := security.GenerateRandomKey(symmKeyDim)

	//CREATE TOKEN
	ticket := messages.Ticket{
		Key:           keyClientTGS,
		ClientId:      req.ClientId,
		ClientAddress: string(clientAddr.IP),
		TGSId:         req.TGSId,
		Timestamp:     timestamp,
		Lifetime:      lifetime,
	}

	//ENCRYPT TOKEN
	jsonTicket, err := json.Marshal(ticket)
	if err != nil {
		return nil, err
	}

	encryptedToken, err := security.SymmetricEncryption(jsonTicket, tgsKey)
	if err != nil {
		return nil, err
	}

	//CREATE RESPONSE
	reply := messages.ASReply{
		KeyClientTGS:  keyClientTGS,
		TGSId:         req.TGSId,
		Timestamp:     timestamp,
		Lifetime:      lifetime,
		CryptedTicket: encryptedToken,
	}

	//ENCRYPT RESPONSE
	jsonReply, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}
	//...

	fmt.Println(len(jsonReply))
	return jsonReply, nil
}

func asErrorHandler(err error) {
	fmt.Println("Error recieving UDP packet")
}
