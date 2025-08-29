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

	if len(os.Args) < 2 {
		fmt.Println("Usage: asconfig <command>")
		fmt.Println("Available commands:")
		fmt.Println("add-client\t\tRegister a new client")
		fmt.Println("show-cleints\t\tShow all the clients registered")
		fmt.Println("get-client\t\tRetrieve a specific client")
		fmt.Println("delete-client\t\tDelete a specific client")
		fmt.Println("add-tgs\t\t\tRegister a new TGS")
		fmt.Println("show-tgs\t\tShow all the TGS registered")
		fmt.Println("get-tgs\t\t\tRetrieve a specific TGS")
		fmt.Println("delete-tgs\t\tDelete a specific TGS")
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "add-client":
		addClient()

	case "show-clients":
		showClients()

	case "get-client":
		getClient()

	case "delete-client":
		deleteClient()

	case "add-tgs":
		addTGS()

	case "show-tgs":
		showTGS()

	case "get-tgs":
		getTGS()

	case "delete-tgs":
		deleteTGS()
	default:
		fmt.Println("Unknown command: ", cmd)
	}

}

// CLIENTS
func readAdminPwAndOpenDb() *sql.DB {
	//GET ADMIN PWD
	fmt.Print("Administrator password: ")
	stdin.Scan()
	adminPwd := url.QueryEscape(stdin.Text())

	//OPEN DB
	db, err := dao.OpenEncryptedASDb(config.AsDbPath, adminPwd)
	if err != nil {
		panic(err)
	}

	return db
}

func showClients() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	//GET ALL CLIENTS
	clients, err := dao.GetAllClients(db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nRegistered clients:")
	for _, c := range clients {
		fmt.Printf("DbId: %d, ClientId: %s, Key: %s\n", c.DbId, c.ClientId, hex.EncodeToString(c.Key))
	}
}

func getClient() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	//GET ADMIN PWD
	fmt.Print("ClientId: ")
	stdin.Scan()
	clientId := stdin.Text()

	//GET CLIENTS
	c, err := dao.GetClientByClientId(clientId, db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nClient:")
	fmt.Printf("DbId: %d, ClientId: %s, Key: %s\n", c.DbId, c.ClientId, hex.EncodeToString(c.Key))
}

func deleteClient() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	//GET ADMIN PWD
	fmt.Print("ClientId: ")
	stdin.Scan()
	clientId := stdin.Text()

	//GET CLIENTS
	err := dao.DeleteClientByClientId(clientId, db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nClient " + clientId + " deleted")
}

func addClient() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	//GET CLIENT DATA
	fmt.Print("Insert new clientId : ")
	stdin.Scan()
	clientId := stdin.Text()

	fmt.Print("Insert password for client " + clientId + ": ")
	stdin.Scan()
	clientPwd := stdin.Text()

	//GENERATE KEY AND SAVE CLIENT
	clientKey, err := security.GenerateClientKeyFromPwd(clientPwd, config.SymmKeyDim)
	if err != nil {
		panic(err)
	}
	dao.InsertClient(clientId, clientKey, db)
}

// TGSERVERS
func showTGS() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	//GET ALL TGS
	tgs, err := dao.GetAllTGS(db)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Println("\nRegistered TGS:")
	for _, t := range tgs {
		fmt.Printf("DbId: %d, TgsId: %s, Key: %s\n", t.DbId, t.TgsId, hex.EncodeToString(t.Key))
	}
}

func getTGS() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	fmt.Print("TgsId: ")
	stdin.Scan()
	tgsId := stdin.Text()

	//GET TGS
	t, err := dao.GetTGSByTgsId(tgsId, db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nClient:")
	fmt.Printf("DbId: %d, TgsId: %s, Key: %s\n", t.DbId, t.TgsId, hex.EncodeToString(t.Key))
}

func deleteTGS() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	fmt.Print("TgsId: ")
	stdin.Scan()
	tgsId := stdin.Text()

	//DELETE TGS
	err := dao.DeleteTGSByTgsId(tgsId, db)
	if err != nil {
		panic(err)
	}
	fmt.Println("\nTGS " + tgsId + " deleted")
}

func addTGS() {
	db := readAdminPwAndOpenDb()
	defer db.Close()

	//GET TGS DATA
	fmt.Print("Insert new TgsId : ")
	stdin.Scan()
	tgsId := stdin.Text()

	fmt.Print("Insert symmetric key file for  " + tgsId + " (OPTIONAL, if not provided a new symmetric key will be generated and printed in the terminal): ")
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
	dao.InsertTGS(tgsId, key, db)
}
