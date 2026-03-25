// Package db provides SQLite-backed storage for RSA keys.
package db

import (
	"database/sql"
	"time"

	// Import sqlite3 driver
_ "github.com/mattn/go-sqlite3"
)

// KeyRecord represents one key row stored in the database.
type KeyRecord struct {
	Kid int
	Key []byte
	Exp int64
}

// DB wraps the SQLite connection used for key storage.
type DB struct {
	conn *sql.DB
}

// NewDB opens or creates the SQLite database at the given path.
func NewDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	return &DB{conn: db}, nil
}

// Init creates the keys table if it does not already exist.
func (d *DB) Init() error {
	query := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`
	_, err := d.conn.Exec(query)
	return err
}

// InsertKey saves a PEM-encoded private key and its expiry into the database.
func (d *DB) InsertKey(key []byte, exp int64) error {
	_, err := d.conn.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		key, exp,
	)
	return err
}

// GetValidKey returns one unexpired key from the database.
func (d *DB) GetValidKey() (KeyRecord, error) {
	row := d.conn.QueryRow(
		`SELECT kid, key, exp FROM keys
		 WHERE exp > ?
		 ORDER BY exp ASC
		 LIMIT 1`,
		time.Now().Unix(),
	)

	var k KeyRecord
	err := row.Scan(&k.Kid, &k.Key, &k.Exp)
	return k, err
}

// GetExpiredKey returns one expired key from the database.
func (d *DB) GetExpiredKey() (KeyRecord, error) {
	row := d.conn.QueryRow(
		`SELECT kid, key, exp FROM keys
		 WHERE exp <= ?
		 ORDER BY exp DESC
		 LIMIT 1`,
		time.Now().Unix(),
	)

	var k KeyRecord
	err := row.Scan(&k.Kid, &k.Key, &k.Exp)
	return k, err
}

// GetValidKeys returns all non-expired keys from the database.
func (d *DB) GetValidKeys() ([]KeyRecord, error) {
	rows, err := d.conn.Query(
		`SELECT kid, key, exp FROM keys WHERE exp > ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
	_ = rows.Close()
}()

	var records []KeyRecord

	for rows.Next() {
		var k KeyRecord
		if err := rows.Scan(&k.Kid, &k.Key, &k.Exp); err != nil {
			return nil, err
		}
		records = append(records, k)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}