package protocol

import (
	"fmt"
	"net"
	"simple_kerberos/internal/network"
)

func StartTGS() {
	serverAddr := net.UDPAddr{
		Port: 8889,
	}

	fmt.Println("Kerberos TGS listening on port 8889...")
	network.ListenUDP(serverAddr, 1024, tgsRequestHandler, tgsErrorHandler)

}

func tgsRequestHandler(data []byte, clientAddr *net.UDPAddr) ([]byte, error) {
	msg := string(data)
	return []byte("Ricevuto: " + msg), nil
}

func tgsErrorHandler(err error) {
	fmt.Println("Error recieving UDP packet")
}
