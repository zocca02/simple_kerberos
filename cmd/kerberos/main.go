package main

import (
	"fmt"
	"simple_kerberos/internal/protocol"
)

// KERBEROS
func main() {
	fmt.Println("Kerberos KDC started")

	endCh := make(chan bool)

	go protocol.StartAS()
	go protocol.StartTGS()

	<-endCh
}
