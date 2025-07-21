package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"simple_kerberos/internal/kerrors"
	"simple_kerberos/internal/messages"
	"simple_kerberos/internal/protocol"
	"strconv"
	"time"
)

var stdin = bufio.NewScanner(os.Stdin)

// CLIENT
func main() {

	if len(os.Args) < 3 {
		fmt.Println("Usage: asconfig <server ip (as, tgs or service)> <command>")
		os.Exit(1)
	}

	serverIp := os.Args[1]
	cmd := os.Args[2]

	switch cmd {
	case "auth-as":
		authAs(serverIp)

	case "auth-tgs":
		authTgs(serverIp)

	case "auth-service":
		authService(serverIp)

	default:
		fmt.Println("Unknown command: ", cmd)
	}

}

func authAs(serverIp string) {

	fmt.Print("Insert your ClientId: ")
	stdin.Scan()
	clientId := stdin.Text()

	fmt.Print("Insert the TgsId of the Ticket Granting server where you want to authenticate: ")
	stdin.Scan()
	tgsId := stdin.Text()

	fmt.Print(clientId + "'s password: ")
	stdin.Scan()
	clientPwd := stdin.Text()

	req := messages.ASRequest{
		ClientId:  clientId,
		TGSId:     tgsId,
		Timestamp: time.Now().UnixMilli(),
	}

	ticketData, err := protocol.RequestToAs(serverIp, req, clientPwd)
	if err != nil && errors.Is(err, &kerrors.ReplyError{}) {
		fmt.Println("Error from AS: ", err)
		os.Exit(1)
	} else if err != nil && errors.Is(err, &kerrors.PasswordError{}) {
		fmt.Println("Wrong password")
		os.Exit(1)
	} else if err != nil {
		fmt.Println(err)
		panic(err)
	}

	err = protocol.SaveTGSTicket(clientId, ticketData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Ticket for "+ticketData.TargetId+" saved with the temporary key in your local database. Expires in ", ticketData.Lifetime/1000/60, " minutes")

}

func authTgs(serverIp string) {

	fmt.Print("Insert your ClientId: ")
	stdin.Scan()
	clientId := stdin.Text()

	fmt.Print("Insert the TgsId of the Ticket Granting server where you want to authenticate: ")
	stdin.Scan()
	tgsId := stdin.Text()

	fmt.Print("Insert the ServiceId of the service where you want to authenticate: ")
	stdin.Scan()
	serviceId := stdin.Text()

	/*
		fmt.Print(clientId + "'s password: ")
		stdin.Scan()
		clientPwd := stdin.Text()
	*/

	tgsTicketData, err := protocol.RetriveTGSTicket(clientId, tgsId)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	req, err := protocol.PrepareTGSRequest(serverIp, clientId, serviceId, tgsTicketData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	serviceTicketData, err := protocol.RequestToTgs(serverIp, req, tgsTicketData)

	if err != nil && errors.Is(err, &kerrors.ReplyError{}) {
		fmt.Println("Error from TGS: ", err)
		os.Exit(1)
	} else if err != nil && errors.Is(err, &kerrors.PasswordError{}) {
		fmt.Println("Wrong client-tgs key")
		os.Exit(1)
	} else if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = protocol.SaveServiceTicket(clientId, serviceTicketData)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Ticket for service "+serviceTicketData.TargetId+" saved with the temporary key in your local database. Expires in ", serviceTicketData.Lifetime/1000/60, " minutes")

}

func authService(serverIp string) {

	fmt.Print("Insert the service port: ")
	stdin.Scan()
	servicePort, err := strconv.ParseInt(stdin.Text(), 10, 32)
	if err != nil {
		fmt.Println("servicePort must be an integer")
		os.Exit(1)
	}

	fmt.Print("Insert your ClientId: ")
	stdin.Scan()
	clientId := stdin.Text()

	fmt.Print("Insert the ServiceId of the service where you want to authenticate: ")
	stdin.Scan()
	serviceId := stdin.Text()

	/*
		fmt.Print(clientId + "'s password: ")
		stdin.Scan()
		clientPwd := stdin.Text()
	*/

	serviceTicketData, err := protocol.RetriveServiceTicket(clientId, serviceId)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	req, serviceTimestamp, err := protocol.PrepareServiceRequest(serverIp, clientId, serviceId, serviceTicketData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	serviceMsg, err := protocol.RequestToService(serverIp, int(servicePort), req, serviceTicketData, serviceTimestamp)

	if err != nil && errors.Is(err, &kerrors.ReplyError{}) {
		fmt.Println("Error from Service "+serviceId+": ", err)
		os.Exit(1)
	} else if err != nil && errors.Is(err, &kerrors.PasswordError{}) {
		fmt.Println("Wrong client-service key")
		os.Exit(1)
	} else if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Service reply: " + serviceMsg)

}
