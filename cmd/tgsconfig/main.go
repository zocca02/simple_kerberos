package main

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	config "simple_kerberos/configs"
	"simple_kerberos/internal/dao"
	"simple_kerberos/internal/security"
	"strings"
)

var stdin = bufio.NewScanner(os.Stdin)

func main() {

	if len(os.Args) < 3 {
		fmt.Println("Usage: tgsconfig tgsName <command>")
		fmt.Println("Available commands:")
		fmt.Println("add-service\t\tRegister a new service")
		fmt.Println("show-services\t\tShow all the services registered")
		fmt.Println("get-service\t\tRetrieve a specific service")
		fmt.Println("delete-service\t\tDelete a specific service")
		os.Exit(1)
	}

	tgsName := os.Args[1]
	cmd := os.Args[2]

	switch cmd {
	case "add-service":
		addService(tgsName)

	case "show-services":
		showServices(tgsName)

	case "get-service":
		getService(tgsName)

	case "delete-service":
		deleteService(tgsName)

	default:
		fmt.Println("Unknown command: ", cmd)
	}

}

func readAdminPwAndOpenDb(tgsName string) *sql.DB {
	//GET ADMIN PWD
	fmt.Print("Administrator password: ")
	stdin.Scan()
	adminPwd := url.QueryEscape(stdin.Text())

	//OPEN DB
	db, err := dao.OpenEncryptedASDb(config.TgsDbPath+tgsName+".db", adminPwd)
	if err != nil {
		panic(err)
	}

	return db
}

func showServices(tgsName string) {
	db := readAdminPwAndOpenDb(tgsName)
	defer db.Close()

	//GET ALL CLIENTS
	services, err := dao.GetAllServices(db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nRegistered services:")
	for _, s := range services {
		fmt.Printf("DbId: %d, ServiceId: %s, Key: %s\n", s.DbId, s.ServiceId, hex.EncodeToString(s.Key))
	}
}

func getService(tgsName string) {
	db := readAdminPwAndOpenDb(tgsName)
	defer db.Close()

	//GET ADMIN PWD
	fmt.Print("ServiceId: ")
	stdin.Scan()
	serviceId := stdin.Text()

	//GET CLIENTS
	s, err := dao.GetServiceByServiceId(serviceId, db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nService:")
	fmt.Printf("DbId: %d, ClientId: %s, Key: %s\n", s.DbId, s.ServiceId, hex.EncodeToString(s.Key))
}

func deleteService(tgsName string) {
	db := readAdminPwAndOpenDb(tgsName)
	defer db.Close()

	//GET ADMIN PWD
	fmt.Print("ServiceId: ")
	stdin.Scan()
	serviceId := stdin.Text()

	//GET CLIENTS
	err := dao.DeleteClientByClientId(serviceId, db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nService " + serviceId + " deleted")
}

func addService(tgsName string) {
	db := readAdminPwAndOpenDb(tgsName)
	defer db.Close()

	//GET TGS DATA
	fmt.Print("Insert new serviceId: ")
	stdin.Scan()
	serviceId := stdin.Text()

	fmt.Print("Insert symmetric key file for  " + serviceId + " (OPTIONAL, if not provided a new symmetric key will be generated and printed in the terminal): ")
	stdin.Scan()
	keyFilePath := strings.TrimSpace(stdin.Text())

	//RETRIVE OR GENERATE KEY
	var key []byte
	if _, err := os.Stat(filepath.Clean(keyFilePath)); keyFilePath == "" || err != nil {
		fmt.Println("File not specified or file not found: generate key")
		key = security.GenerateRandomKey(config.SymmKeyDim)
		fmt.Println(hex.EncodeToString(key))
	} else {
		key, err = os.ReadFile(filepath.Clean(keyFilePath))
		if err != nil {
			panic(err)
		}
		key, err = hex.DecodeString(string(key))
		if err != nil {
			fmt.Println("ERROR: Malformed key")
			os.Exit(1)
		}
		if len(key) != config.SymmKeyDim/8 {
			fmt.Println("ERROR: Key lenght not matching with symmetric key dim")
			os.Exit(1)
		}
	}

	//SAVE TGS
	dao.InsertService(serviceId, key, db)
}
