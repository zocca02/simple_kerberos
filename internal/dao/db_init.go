package dao

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	//_ "github.com/mattn/go-sqlite3"
	_ "github.com/mutecomm/go-sqlcipher"
)

func InitNewEncryptedASDbIfNotExists(path string, pwd string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		err := InitNewEncryptedASDb(path, pwd)

		if err != nil {
			return err
		}
	}

	return nil
}

func InitNewEncryptedASDb(path string, pwd string) error {
	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma_key="+pwd+"&_pragma_cipher_page_size=4096")
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS clients (
            id 			INTEGER PRIMARY KEY AUTOINCREMENT,
            clientId 	TEXT NOT NULL UNIQUE,
			key 		BLOB NOT NULL
        );

		CREATE TABLE IF NOT EXISTS tgservers (
            id 			INTEGER PRIMARY KEY AUTOINCREMENT,
            tgsId	 	TEXT NOT NULL UNIQUE,
			key 		BLOB NOT NULL
        );
    `)
	if err != nil {
		return err
	}

	return nil
}

func InitNewEncryptedTGSDbIfNotExists(path string, pwd string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		err := InitNewEncryptedTGSDb(path, pwd)
		if err != nil {
			return err
		}
	}

	return nil
}

func InitNewEncryptedTGSDb(path string, pwd string) error {
	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma_key="+pwd+"&_pragma_cipher_page_size=4096")
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS services (
            id 			INTEGER PRIMARY KEY AUTOINCREMENT,
            serviceId	TEXT NOT NULL UNIQUE,
			key 		BLOB NOT NULL
        );

		CREATE TABLE IF NOT EXISTS config (
			id			INTEGER PRIMARY KEY AUTOINCREMENT,
			tgsId		TEXT NOT NULL UNIQUE,
			asKey 		BLOB NOT NULL
		);
    `)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func InitNewClientDbIfNotExists(path string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		err := InitNewClientDb(path)

		if err != nil {
			return err
		}
	}

	return nil
}

func InitNewClientDb(path string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS tgsTickets (
            id 			INTEGER PRIMARY KEY AUTOINCREMENT,
            clientId 	TEXT NOT NULL UNIQUE,
			tgsId 		TEXT NOT NULL UNIQUE,
			ticket		BLOB NOT NULL,
			ticketMac	BLOB NOT NULL,
			key 		BLOB NOT NULL,
			lifetime	BIGINT,
			issueTime	BIGINT		
        );

		CREATE TABLE IF NOT EXISTS serviceTickets (
            id 			INTEGER PRIMARY KEY AUTOINCREMENT,
            clientId 	TEXT NOT NULL UNIQUE,
			serviceId	TEXT NOT NULL UNIQUE,
			ticket		BLOB NOT NULL,
			ticketMac	BLOB NOT NULL,
			key 		BLOB NOT NULL,
			lifetime	BIGINT,
			issueTime	BIGINT	
        );
    `)
	if err != nil {
		return err
	}

	return nil
}

func OpenEncryptedASDb(path string, pwd string) (*sql.DB, error) {

	//INIT DBs IF NOT EXIST
	err := InitNewEncryptedASDbIfNotExists(path, pwd)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma_key="+pwd+"&_pragma_cipher_page_size=4096")
	if err != nil {
		return nil, err
	}

	return db, nil
}

func OpenEncryptedTGSDb(path string, pwd string) (*sql.DB, error) {

	//INIT DBs IF NOT EXIST
	err := InitNewEncryptedTGSDbIfNotExists(path, pwd)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma_key="+pwd+"&_pragma_cipher_page_size=4096")
	if err != nil {
		return nil, err
	}

	return db, nil
}

func OpenDb(path string) (*sql.DB, error) {

	//INIT DBs IF NOT EXIST
	err := InitNewClientDbIfNotExists(path)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	return db, nil
}
