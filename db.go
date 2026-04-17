package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database for scan persistence.
type DB struct {
	conn *sql.DB
}

// OpenDB opens or creates the OSCAR SQLite database.
func OpenDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (d *DB) Close() {
	d.conn.Close()
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		target    TEXT NOT NULL,
		started   DATETIME NOT NULL,
		finished  DATETIME,
		status    TEXT DEFAULT 'running'
	);

	CREATE TABLE IF NOT EXISTS subdomains (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id  INTEGER REFERENCES scans(id),
		host     TEXT NOT NULL,
		ip       TEXT,
		cname    TEXT,
		alive    BOOLEAN DEFAULT FALSE,
		UNIQUE(scan_id, host)
	);

	CREATE TABLE IF NOT EXISTS services (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER REFERENCES scans(id),
		host        TEXT NOT NULL,
		port        INTEGER,
		url         TEXT,
		status_code INTEGER,
		title       TEXT,
		tech        TEXT,
		UNIQUE(scan_id, host, port)
	);

	CREATE TABLE IF NOT EXISTS urls (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id  INTEGER REFERENCES scans(id),
		url      TEXT NOT NULL,
		source   TEXT,
		UNIQUE(scan_id, url)
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER REFERENCES scans(id),
		host        TEXT,
		template_id TEXT,
		name        TEXT,
		severity    TEXT,
		matched     TEXT,
		description TEXT,
		found_at    DATETIME
	);`

	_, err := d.conn.Exec(schema)
	return err
}

// StartScan creates a new scan record and returns its ID.
func (d *DB) StartScan(target string) (int64, error) {
	res, err := d.conn.Exec(
		`INSERT INTO scans (target, started, status) VALUES (?, ?, 'running')`,
		target, time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScan marks a scan as complete.
func (d *DB) FinishScan(id int64) {
	d.conn.Exec( //nolint:errcheck
		`UPDATE scans SET finished = ?, status = 'done' WHERE id = ?`,
		time.Now(), id,
	)
}

// InsertSubdomain adds a subdomain record (ignores duplicates).
func (d *DB) InsertSubdomain(scanID int64, host, ip, cname string, alive bool) {
	d.conn.Exec( //nolint:errcheck
		`INSERT OR IGNORE INTO subdomains (scan_id, host, ip, cname, alive) VALUES (?, ?, ?, ?, ?)`,
		scanID, host, ip, cname, alive,
	)
}

// InsertVuln adds a vulnerability finding.
func (d *DB) InsertVuln(scanID int64, host, templateID, name, severity, matched, description string) {
	d.conn.Exec( //nolint:errcheck
		`INSERT INTO vulnerabilities (scan_id, host, template_id, name, severity, matched, description, found_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, host, templateID, name, severity, matched, description, time.Now(),
	)
}
