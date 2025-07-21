package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	config "simple_kerberos/configs"
	"simple_kerberos/internal/protocol"
	"strconv"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: service serviceId serviceIp servicePort")
		os.Exit(1)
	}

	serviceId := os.Args[1]
	serviceIp := os.Args[2]
	servicePort, err := strconv.ParseInt(os.Args[3], 10, 32)
	if err != nil {
		fmt.Println("servicePort must be an integer")
		os.Exit(1)
	}

	var key []byte
	keyFilePath := config.ServiceKeyPath + serviceId + ".key"
	if _, err := os.Stat(filepath.Clean(keyFilePath)); keyFilePath == "" || err != nil {
		fmt.Println("Can't find " + serviceId + ".key file")
		os.Exit(1)
	}

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

	protocol.StartService(serviceIp, int(servicePort), serviceId, key)
}
