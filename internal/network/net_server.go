package network

import (
	"net"
)

func ListenUDP(serverAddr net.UDPAddr, bufferSize int, onRequest func([]byte, *net.UDPAddr) ([]byte, error), onError func(err error)) {

	conn, err := net.ListenUDP("udp", &serverAddr)

	if err != nil {
		panic(err)
	}

	defer conn.Close()
	buffer := make([]byte, bufferSize)

	for {
		len, clientAddr, err := conn.ReadFromUDP(buffer)

		if err != nil {
			onError(err)
			continue
		}

		responseData, err := onRequest(buffer[:len], clientAddr)
		if err != nil {
			onError(err)
			continue
		}
		conn.WriteToUDP(responseData, clientAddr)
	}
}
