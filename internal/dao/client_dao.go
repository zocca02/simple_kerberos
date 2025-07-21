package dao

import (
	"database/sql"
	"simple_kerberos/internal/dto"
)

// INSERT
func InsertTGSTicket(clientId string, data dto.TicketData, db *sql.DB) error {
	query := `INSERT INTO tgsTickets (clientId, tgsId, ticket, ticketMac, key, lifetime, issueTime) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := db.Exec(query, clientId, data.TargetId, data.EncryptedTicket, data.EncTicketMac, data.Key, data.Lifetime, data.Timestamp)
	return err
}

func InsertServiceTicket(clientId string, data dto.TicketData, db *sql.DB) error {
	query := `INSERT INTO serviceTickets (clientId, serviceId, ticket, ticketMac, key, lifetime, issueTime) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := db.Exec(query, clientId, data.TargetId, data.EncryptedTicket, data.EncTicketMac, data.Key, data.Lifetime, data.Timestamp)
	return err
}

//UPDATE

func UpdateTGSTicket(clientId string, data dto.TicketData, db *sql.DB) error {
	query := `UPDATE tgsTickets SET ticket = $1, ticketMac = $2, lifetime = $3, issueTime = $4, key=$5 WHERE clientId = $6`
	_, err := db.Exec(query, data.EncryptedTicket, data.EncTicketMac, data.Lifetime, data.Timestamp, data.Key, clientId)
	return err
}

func UpdateServiceTicket(clientId string, data dto.TicketData, db *sql.DB) error {
	query := `UPDATE serviceTickets SET ticket = $1, ticketMac = $2, lifetime = $3, issueTime = $4, key=$5 WHERE clientId = $6`
	_, err := db.Exec(query, data.EncryptedTicket, data.EncTicketMac, data.Lifetime, data.Timestamp, data.Key, clientId)
	return err
}

// EXISTS
func ServiceTicketExists(clientId, serviceId string, db *sql.DB) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM serviceTickets WHERE clientId = $1 AND serviceId = $2)`
	err := db.QueryRow(query, clientId, serviceId).Scan(&exists)
	return exists, err
}

func TGSTicketExists(clientId, tgsId string, db *sql.DB) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM tgsTickets WHERE clientId = $1 AND tgsId = $2)`
	err := db.QueryRow(query, clientId, tgsId).Scan(&exists)
	return exists, err
}

// DELETE
func DeleteTGSTicket(clientId, tgsId string, db *sql.DB) error {
	query := `DELETE FROM tgsTickets WHERE clientId = $1 AND tgsId = $2`
	_, err := db.Exec(query, clientId, tgsId)
	return err
}

func DeleteServiceTicket(clientId, serviceId string, db *sql.DB) error {
	query := `DELETE FROM serviceTickets WHERE clientId = $1 AND serviceId = $2`
	_, err := db.Exec(query, clientId, serviceId)
	return err
}

// SELECT
func GetTGSTicket(clientId, tgsId string, db *sql.DB) (dto.TicketData, error) {
	var td dto.TicketData
	query := `SELECT key, tgsId, issueTime, lifetime, ticket, ticketMac FROM tgsTickets WHERE clientId = $1 AND tgsId = $2`
	err := db.QueryRow(query, clientId, tgsId).Scan(&td.Key, &td.TargetId, &td.Timestamp, &td.Lifetime, &td.EncryptedTicket, &td.EncTicketMac)
	return td, err
}

func GetServiceTicket(clientId, serviceId string, db *sql.DB) (dto.TicketData, error) {
	var td dto.TicketData
	query := `SELECT key, serviceId, issueTime, lifetime, ticket, ticketMac FROM serviceTickets WHERE clientId = $1 AND serviceId = $2`
	err := db.QueryRow(query, clientId, serviceId).Scan(&td.Key, &td.TargetId, &td.Timestamp, &td.Lifetime, &td.EncryptedTicket, &td.EncTicketMac)
	return td, err
}
