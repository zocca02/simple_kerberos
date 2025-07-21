package network

import (
	"net"
)

func SendUDPRequest(localAddr *net.UDPAddr, serverAddr *net.UDPAddr, data []byte, bufferSize int) ([]byte, error) {

	conn, err := net.DialUDP("udp", localAddr, serverAddr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
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

func GetActiveIP(destIp string) (net.IP, error) {
	conn, err := net.Dial("udp", destIp+":8000") //dummy port 8000
	if err != nil {
		return net.IP{}, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}
