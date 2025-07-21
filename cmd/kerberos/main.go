package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	config "simple_kerberos/configs"
	"simple_kerberos/internal/dao"
	"simple_kerberos/internal/protocol"
	"simple_kerberos/internal/security"
)

var stdin = bufio.NewScanner(os.Stdin)

// KERBEROS
func main() {
	fmt.Println("Kerberos KDC started")

	//READ ADMIN PWD
	fmt.Print("Administrator password: ")
	stdin.Scan()
	adminPwd := url.QueryEscape(stdin.Text())

	if !checkDbPwd(adminPwd) {
		fmt.Println("Wrong admin password or problems with db")
		os.Exit(1)
	}

	endCh := make(chan bool)

	for i, tgsId := range config.TgsList {

		initTgsConfigIfNotExists(tgsId, adminPwd)

		key := retriveTgsConfig(tgsId, adminPwd)

		if err := protocol.AddTGS(tgsId, key, adminPwd); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		go protocol.StartTGS("127.0.0."+fmt.Sprint(i+2), tgsId, key, adminPwd)
	}

	go protocol.StartAS("127.0.0.1", adminPwd)

	<-endCh
}

func checkDbPwd(pwd string) bool {
	db, err := dao.OpenEncryptedASDb(config.AsDbPath, pwd)

	if err != nil {
		fmt.Println("Db opening problem: ", err)
		os.Exit(1)
	}
	defer db.Close()

	var result int
	err = db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&result)
	if err != nil {
		return false
	}

	for _, tgsId := range config.TgsList {

		db, err = dao.OpenEncryptedTGSDb(config.TgsDbPath+tgsId+".db", pwd)

		if err != nil {
			fmt.Println("Db opening problem: ", err)
			os.Exit(1)
		}
		defer db.Close()

		err = db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&result)

		if err != nil {
			return false
		}
	}

	return true
}

func initTgsConfigIfNotExists(tgsId string, adminPwd string) {

	db, err := dao.OpenEncryptedTGSDb(config.TgsDbPath+tgsId+".db", adminPwd)
	if err != nil {
		fmt.Println("Db opening problem: ", err)
		os.Exit(1)
	}
	defer db.Close()

	exists, err := dao.TgsConfigExists(db)
	if err != nil {
		fmt.Println("Db opening problem: ", err)
		os.Exit(1)
	}
	if exists {
		return
	}

	key := security.GenerateRandomKey(config.SymmKeyDim)

	dao.InsertTgsConfig(tgsId, key, db)
}

func retriveTgsConfig(tgsId string, adminPwd string) []byte {

	db, err := dao.OpenEncryptedTGSDb(config.TgsDbPath+tgsId+".db", adminPwd)
	if err != nil {
		fmt.Println("Db opening problem: ", err)
		os.Exit(1)
	}

	_, key, err := dao.GetTgsConfig(db)
	if err != nil {
		fmt.Println("Db opening problem: ", err)
		os.Exit(1)
	}

	return key

}
