package network

import "net"

func SetupClientUDPConnection(serverAddr *net.UDPAddr) *net.UDPConn {
	conn, err := net.DialUDP("udp", nil, serverAddr)

	if err != nil {
		panic(err)
	}

	return conn
}

func SendUDPRequest(conn *net.UDPConn, data []byte, bufferSize int) ([]byte, error) {
	_, err := conn.Write(data)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 1024)
	len, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:len], nil
}
