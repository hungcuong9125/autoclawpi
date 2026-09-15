// Package db menyediakan akses SQLite untuk autoclawpi.
// Schema: accounts + checkin_log + config.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// Account menyimpan satu akun AutoClaw.
type Account struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	AccessToken  string `json:"-"` // plaintext di memory, encrypted di disk
	RefreshToken string `json:"-"`
	Provider     string `json:"provider"` // zai | google
	UserID       string `json:"user_id"`
	UserName     string `json:"user_name"`
	DeviceID     string `json:"device_id"`
	Points       int    `json:"points"`
	Active       bool   `json:"active"`
	CreatedAt    string `json:"created_at"`
	LastUsedAt   string `json:"last_used_at"`
}

// CheckinLog mencatat history check-in.
type CheckinLog struct {
	ID        int64  `json:"id"`
	AccountID int64  `json:"account_id"`
	Date      string `json:"date"`    // YYYY-MM-DD
	TaskID    string `json:"task_id"` // daily_signin, dll
	Points    int    `json:"points"`
	Status    string `json:"status"` // success | already_done | failed
	DeviceID  string `json:"device_id"`
	CreatedAt string `json:"created_at"`
}

// Init membuka/membuat database dan menjalankan migrasi.
func Init(dir string) error {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(home, ".autoclawpi")
	}
	_ = os.MkdirAll(dir, 0o700)
	dbPath := filepath.Join(dir, "autoclawpi.db")

	var err error
	DB, err = sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	DB.SetMaxOpenConns(1) // SQLite single-writer

	if err := migrate(); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Close menutup database.
func Close() {
	if DB != nil {
		DB.Close()
	}
}

func migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS accounts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL DEFAULT '',
		access_token TEXT NOT NULL DEFAULT '',
		refresh_token TEXT NOT NULL DEFAULT '',
		provider TEXT NOT NULL DEFAULT 'zai',
		user_id TEXT NOT NULL DEFAULT '',
		user_name TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL DEFAULT '',
		points INTEGER NOT NULL DEFAULT 0,
		active INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		last_used_at TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS checkin_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL,
		date TEXT NOT NULL,
		task_id TEXT NOT NULL,
		points INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'failed',
		device_id TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id)
	);

	CREATE INDEX IF NOT EXISTS idx_checkin_log_account_date ON checkin_log(account_id, date);

	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL DEFAULT 0,
		model TEXT NOT NULL DEFAULT '',
		prompt_tokens INTEGER NOT NULL DEFAULT 0,
		completion_tokens INTEGER NOT NULL DEFAULT 0,
		total_tokens INTEGER NOT NULL DEFAULT 0,
		cost REAL NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'success',
		error TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	`
	_, err := DB.Exec(schema)
	return err
}

// --- Account CRUD ---

// AddAccount menyimpan akun baru.
func AddAccount(name, accessToken, refreshToken, provider, userID, userName, deviceID string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := DB.Exec(`INSERT INTO accounts (name, access_token, refresh_token, provider, user_id, user_name, device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name, accessToken, refreshToken, provider, userID, userName, deviceID, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAccounts mengembalikan semua akun.
func ListAccounts() ([]Account, error) {
	rows, err := DB.Query(`SELECT id, name, access_token, refresh_token, provider, user_id, user_name, device_id, points, active, created_at, last_used_at FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Name, &a.AccessToken, &a.RefreshToken, &a.Provider, &a.UserID, &a.UserName, &a.DeviceID, &a.Points, &a.Active, &a.CreatedAt, &a.LastUsedAt); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

// GetAccount mengambil satu akun berdasarkan ID.
func GetAccount(id int64) (*Account, error) {
	row := DB.QueryRow(`SELECT id, name, access_token, refresh_token, provider, user_id, user_name, device_id, points, active, created_at, last_used_at FROM accounts WHERE id = ?`, id)
	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.AccessToken, &a.RefreshToken, &a.Provider, &a.UserID, &a.UserName, &a.DeviceID, &a.Points, &a.Active, &a.CreatedAt, &a.LastUsedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// GetActiveAccount mengembalikan akun aktif pertama (untuk single-account mode).
func GetActiveAccount() (*Account, error) {
	row := DB.QueryRow(`SELECT id, name, access_token, refresh_token, provider, user_id, user_name, device_id, points, active, created_at, last_used_at FROM accounts WHERE active = 1 ORDER BY id LIMIT 1`)
	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.AccessToken, &a.RefreshToken, &a.Provider, &a.UserID, &a.UserName, &a.DeviceID, &a.Points, &a.Active, &a.CreatedAt, &a.LastUsedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// UpdateAccount memperbarui data akun.
func UpdateAccount(a *Account) error {
	_, err := DB.Exec(`UPDATE accounts SET name=?, access_token=?, refresh_token=?, provider=?, user_id=?, user_name=?, device_id=?, points=?, active=?, last_used_at=? WHERE id=?`,
		a.Name, a.AccessToken, a.RefreshToken, a.Provider, a.UserID, a.UserName, a.DeviceID, a.Points, a.Active, a.LastUsedAt, a.ID)
	return err
}

// DeleteAccount menghapus akun.
func DeleteAccount(id int64) error {
	_, err := DB.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// SetAccountActive mengaktifkan/menonaktifkan akun.
// Dipakai untuk mengarantina akun yang ditolak permanen oleh upstream
// (mis. kode 410004 账号已被封禁) supaya tidak dicoba berulang kali.
func SetAccountActive(id int64, active bool) error {
	_, err := DB.Exec(`UPDATE accounts SET active = ? WHERE id = ?`, active, id)
	return err
}

// UpdateAccountTokens menyimpan token hasil refresh tanpa menyentuh field lain.
func UpdateAccountTokens(id int64, accessToken, refreshToken string) error {
	_, err := DB.Exec(`UPDATE accounts SET access_token = ?, refresh_token = ? WHERE id = ?`,
		accessToken, refreshToken, id)
	return err
}

// UpdatePoints menambah poin akun.
func UpdatePoints(id int64, points int) error {
	_, err := DB.Exec(`UPDATE accounts SET points = ? WHERE id = ?`, points, id)
	return err
}

// --- Checkin Log ---

// AddCheckinLog mencatat hasil check-in.
func AddCheckinLog(accountID int64, date, taskID string, points int, status, deviceID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := DB.Exec(`INSERT INTO checkin_log (account_id, date, task_id, points, status, device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		accountID, date, taskID, points, status, deviceID, now)
	return err
}

// GetCheckinLog mengembalikan log check-in untuk akun pada tanggal tertentu.
func GetCheckinLog(accountID int64, date, taskID string) (*CheckinLog, error) {
	row := DB.QueryRow(`SELECT id, account_id, date, task_id, points, status, device_id, created_at FROM checkin_log WHERE account_id = ? AND date = ? AND task_id = ?`, accountID, date, taskID)
	var l CheckinLog
	if err := row.Scan(&l.ID, &l.AccountID, &l.Date, &l.TaskID, &l.Points, &l.Status, &l.DeviceID, &l.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &l, nil
}

// ListCheckinLog mengembalikan semua log check-in untuk akun.
func ListCheckinLog(accountID int64, limit int) ([]CheckinLog, error) {
	rows, err := DB.Query(`SELECT id, account_id, date, task_id, points, status, device_id, created_at FROM checkin_log WHERE account_id = ? ORDER BY created_at DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []CheckinLog
	for rows.Next() {
		var l CheckinLog
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Date, &l.TaskID, &l.Points, &l.Status, &l.DeviceID, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// --- Config ---

// GetConfig mengambil nilai konfigurasi.
func GetConfig(key string) (string, error) {
	row := DB.QueryRow(`SELECT value FROM config WHERE key = ?`, key)
	var val string
	if err := row.Scan(&val); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// SetConfig menyimpan nilai konfigurasi.
func SetConfig(key, value string) error {
	_, err := DB.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`, key, value)
	return err
}

// ── Logs ────────────────────────────────────────────────────────────

type LogEntry struct {
	ID               int64   `json:"id"`
	AccountID        int64   `json:"account_id"`
	Model            string  `json:"model"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	Cost             float64 `json:"cost"`
	Status           string  `json:"status"`
	Error            string  `json:"error"`
	CreatedAt        string  `json:"created_at"`
}

func AddLog(l *LogEntry) (int64, error) {
	res, err := DB.Exec(`INSERT INTO logs (account_id, model, prompt_tokens, completion_tokens, total_tokens, cost, status, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		l.AccountID, l.Model, l.PromptTokens, l.CompletionTokens, l.TotalTokens, l.Cost, l.Status, l.Error)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func ListLogs(limit int) ([]LogEntry, error) {
	if limit < 1 {
		limit = 50
	}
	rows, err := DB.Query(`SELECT id, account_id, model, prompt_tokens, completion_tokens, total_tokens, cost, status, error, created_at FROM logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Model, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.Cost, &l.Status, &l.Error, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func LogStats() (totalReq int, totalTokens int, totalCost float64, err error) {
	err = DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total_tokens),0), COALESCE(SUM(cost),0) FROM logs WHERE created_at >= datetime('now', 'start of day')`).Scan(&totalReq, &totalTokens, &totalCost)
	return
}
