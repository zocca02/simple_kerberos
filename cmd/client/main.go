package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"simple_kerberos/internal/messages"
	"simple_kerberos/internal/network"
	"time"
)

// CLIENT
func main() {
	fmt.Println("Client started")

	serverAddr := net.UDPAddr{
		Port: 8888,
		IP:   net.ParseIP("127.0.0.1"),
	}

	conn := network.SetupClientUDPConnection(&serverAddr)
	defer conn.Close()

	stdin := bufio.NewScanner(os.Stdin)

	for {

		fmt.Print("Inserisci il tuo client ID: ")
		stdin.Scan()
		clientId := stdin.Text()

		fmt.Print("Inserisci l'ID del TGS: ")
		stdin.Scan()
		tgsId := stdin.Text()

		fmt.Println(clientId)
		fmt.Println(tgsId)

		req := messages.ASRequest{
			ClientId:  clientId,
			TGSId:     tgsId,
			Timestamp: time.Now().UnixMilli(),
		}

		jsonReq, err := json.Marshal(req)

		if err != nil {
			panic(err)
		}

		fmt.Println(string(jsonReq))

		data, err := network.SendUDPRequest(conn, jsonReq, 1024)

		if err != nil {
			fmt.Println("Errore di scrittura:", err)
		}

		fmt.Println("Risposta dal server: " + string(data))
	}

}
