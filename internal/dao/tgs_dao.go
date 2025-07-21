package dao

import (
	"database/sql"
	"simple_kerberos/internal/dto"
)

func InsertService(serviceId string, serviceKey []byte, db *sql.DB) error {
	query := `INSERT INTO services (serviceId, key) VALUES ($1, $2)`
	_, err := db.Exec(query, serviceId, serviceKey)
	return err
}

func GetAllServices(db *sql.DB) ([]dto.Service, error) {
	query := "SELECT id, serviceId, key FROM services"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []dto.Service
	for rows.Next() {
		var s dto.Service
		err := rows.Scan(&s.DbId, &s.ServiceId, &s.Key)
		if err != nil {
			return nil, err
		}
		services = append(services, s)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return services, nil
}

func GetServiceByServiceId(serviceId string, db *sql.DB) (dto.Service, error) {
	query := "SELECT id, serviceId, key FROM services WHERE serviceId = $1"
	var s dto.Service
	err := db.QueryRow(query, serviceId).Scan(&s.DbId, &s.ServiceId, &s.Key)
	return s, err
}

func DeleteServiceByServiceId(serviceId string, db *sql.DB) error {
	query := "DELETE FROM services WHERE serviceId = $1"
	_, err := db.Exec(query, serviceId)
	return err
}

func InsertTgsConfig(tgsId string, asKey []byte, db *sql.DB) error {
	query := `INSERT INTO config (tgsId, asKey) VALUES ($1, $2)`
	_, err := db.Exec(query, tgsId, asKey)
	return err
}

func UpdateTgsConfig(tgsId string, asKey []byte, db *sql.DB) error {
	query := `UPDATE config SET tgsId = $1, asKey = $2 WHERE id = 1`
	_, err := db.Exec(query, tgsId, asKey)
	return err
}

func GetTgsConfig(db *sql.DB) (string, []byte, error) {
	var tgsId string
	var asKey []byte
	query := `SELECT tgsId, asKey FROM config LIMIT 1`
	err := db.QueryRow(query).Scan(&tgsId, &asKey)
	return tgsId, asKey, err
}

func TgsConfigExists(db *sql.DB) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM config)`
	err := db.QueryRow(query).Scan(&exists)
	return exists, err
}

func ServiceExists(serviceID string, db *sql.DB) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM services WHERE serviceId = ? LIMIT 1)`
	err := db.QueryRow(query, serviceID).Scan(&exists)
	return exists, err
}
