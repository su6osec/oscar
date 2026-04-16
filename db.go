package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func InitDB(filepath string) {
	var err error
	db, err = sql.Open("sqlite", filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal Error connecting to embedded SQLite engine: %v\n", err)
		os.Exit(1)
	}

	createSchema()
}

func createSchema() {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		root_domain TEXT UNIQUE NOT NULL,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER,
		url TEXT UNIQUE NOT NULL,
		status_code INTEGER,
		title TEXT,
		server TEXT,
		tech TEXT,
		cname TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(target_id) REFERENCES targets(id)
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		endpoint_id INTEGER,
		severity TEXT,
		description TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
	);
	`
	_, err := db.Exec(schema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal schema generation error: %v\n", err)
		os.Exit(1)
	}
}


