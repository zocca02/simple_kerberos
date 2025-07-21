package dao

import (
	"database/sql"
	"simple_kerberos/internal/dto"
)

func InsertClient(clientId string, clientKey []byte, db *sql.DB) error {
	query := `INSERT INTO clients (clientId, key) VALUES ($1, $2)`
	_, err := db.Exec(query, clientId, clientKey)
	return err
}

func GetAllClients(db *sql.DB) ([]dto.Client, error) {
	query := "SELECT id, clientId, key FROM clients"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []dto.Client
	for rows.Next() {
		var c dto.Client
		err := rows.Scan(&c.DbId, &c.ClientId, &c.Key)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

func GetClientByClientId(clientId string, db *sql.DB) (dto.Client, error) {
	query := "SELECT id, clientId, key FROM clients WHERE clientId = $1"
	var c dto.Client
	err := db.QueryRow(query, clientId).Scan(&c.DbId, &c.ClientId, &c.Key)
	return c, err
}

func DeleteClientByClientId(clientId string, db *sql.DB) error {
	query := "DELETE FROM clients WHERE clientId = $1"
	_, err := db.Exec(query, clientId)
	return err
}

func InsertTGS(tgsId string, tgsKey []byte, db *sql.DB) error {
	query := `INSERT INTO tgservers (tgsId, key) VALUES ($1, $2)`
	_, err := db.Exec(query, tgsId, tgsKey)
	return err
}

func GetAllTGS(db *sql.DB) ([]dto.TGS, error) {
	query := "SELECT id, tgsId, key FROM tgservers"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tgs []dto.TGS
	for rows.Next() {
		var t dto.TGS
		err := rows.Scan(&t.DbId, &t.TgsId, &t.Key)
		if err != nil {
			return nil, err
		}
		tgs = append(tgs, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return tgs, nil
}

func GetTGSByTgsId(tgsId string, db *sql.DB) (dto.TGS, error) {
	query := "SELECT id, tgsId, key FROM tgservers WHERE tgsId = $1"
	var t dto.TGS
	err := db.QueryRow(query, tgsId).Scan(&t.DbId, &t.TgsId, &t.Key)
	return t, err

}

func DeleteTGSByTgsId(tgsId string, db *sql.DB) error {
	query := "DELETE FROM tgservers WHERE tgsId = $1"
	_, err := db.Exec(query, tgsId)
	return err
}

func TgsExists(tgsID string, db *sql.DB) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM tgservers WHERE tgsId = ? LIMIT 1)`
	err := db.QueryRow(query, tgsID).Scan(&exists)
	return exists, err
}

func UpdateTgsKey(tgsID string, newKey []byte, db *sql.DB) error {
	query := `UPDATE tgservers SET key = ? WHERE tgsId = ?`
	_, err := db.Exec(query, newKey, tgsID)
	return err
}
