package relay

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type ServerRecord struct {
	ID           int64
	Name         string
	TokenHash    string
	RelayPort    int
	ProxyEnabled bool
	AdminEnabled bool
	DefaultUser  string
	AgentVersion string
	Hostname     string
	LastSeen     string
	CreatedAt    string
}

type UserRecord struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string // "admin" | "member"
	Enabled      bool
	CreatedAt    string
}

type UserKey struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	PublicKey string `json:"public_key"`
	Comment   string `json:"comment"`
}

type LogRecord struct {
	ID       int64  `json:"id"`
	TS       string `json:"ts"`
	ServerID int64  `json:"server_id"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	User     string `json:"user"`
}

func HashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func OpenStore(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.ensureSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ensureSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS servers (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	token_hash TEXT NOT NULL,
	relay_port INTEGER NOT NULL,
	proxy_enabled INTEGER NOT NULL DEFAULT 0,
	admin_enabled INTEGER NOT NULL DEFAULT 1,
	agent_version TEXT NOT NULL DEFAULT '',
	hostname TEXT NOT NULL DEFAULT '',
	last_seen TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	server_id INTEGER NOT NULL,
	kind TEXT NOT NULL,
	detail TEXT NOT NULL,
	user TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'member',
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	public_key TEXT NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	UNIQUE(public_key)
);
CREATE TABLE IF NOT EXISTS sessions (
	token TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL
);`)
	if err != nil {
		return err
	}
	// 轻量迁移：老库补 default_user / user 列
	_, _ = s.db.Exec(`ALTER TABLE servers ADD COLUMN default_user TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE audit_log ADD COLUMN user TEXT NOT NULL DEFAULT ''`)
	return err
}

const serverCols = `id, name, token_hash, relay_port, proxy_enabled, admin_enabled,
	default_user, agent_version, hostname, last_seen, created_at`

func scanServer(row *sql.Row) (ServerRecord, error) {
	var r ServerRecord
	var proxy, admin int
	err := row.Scan(&r.ID, &r.Name, &r.TokenHash, &r.RelayPort, &proxy, &admin,
		&r.DefaultUser, &r.AgentVersion, &r.Hostname, &r.LastSeen, &r.CreatedAt)
	if err != nil {
		return ServerRecord{}, err
	}
	r.ProxyEnabled = proxy != 0
	r.AdminEnabled = admin != 0
	return r, nil
}

func (s *Store) GetServer(id int64) (ServerRecord, error) {
	return scanServer(s.db.QueryRow(`SELECT `+serverCols+` FROM servers WHERE id=?`, id))
}

func (s *Store) GetServerByName(name string) (ServerRecord, error) {
	return scanServer(s.db.QueryRow(`SELECT `+serverCols+` FROM servers WHERE name=?`, name))
}

func (s *Store) ListServers() ([]ServerRecord, error) {
	rows, err := s.db.Query(`SELECT ` + serverCols + ` FROM servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServerRecord
	for rows.Next() {
		var r ServerRecord
		var proxy, admin int
		if err := rows.Scan(&r.ID, &r.Name, &r.TokenHash, &r.RelayPort, &proxy, &admin,
			&r.DefaultUser, &r.AgentVersion, &r.Hostname, &r.LastSeen, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.ProxyEnabled = proxy != 0
		r.AdminEnabled = admin != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateServer(name, token string, port int) (ServerRecord, error) {
	now := time.Now().Format(time.RFC3339)
	res, err := s.db.Exec(
		`INSERT INTO servers(name, token_hash, relay_port, created_at) VALUES(?,?,?,?)`,
		name, HashToken(token), port, now)
	if err != nil {
		return ServerRecord{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetServer(id)
}

func (s *Store) DeleteServer(id int64) error {
	_, err := s.db.Exec(`DELETE FROM servers WHERE id=?`, id)
	return err
}

func (s *Store) SetToken(id int64, token string) error {
	_, err := s.db.Exec(`UPDATE servers SET token_hash=? WHERE id=?`, HashToken(token), id)
	return err
}

func (s *Store) SetAdminEnabled(id int64, on bool) error {
	_, err := s.db.Exec(`UPDATE servers SET admin_enabled=? WHERE id=?`, boolToInt(on), id)
	return err
}

func (s *Store) SetProxyEnabled(id int64, on bool) error {
	_, err := s.db.Exec(`UPDATE servers SET proxy_enabled=? WHERE id=?`, boolToInt(on), id)
	return err
}

func (s *Store) SetDefaultUser(id int64, user string) error {
	_, err := s.db.Exec(`UPDATE servers SET default_user=? WHERE id=?`, user, id)
	return err
}

func (s *Store) UpdateOnline(id int64, hostname, version string) error {
	_, err := s.db.Exec(
		`UPDATE servers SET hostname=?, agent_version=?, last_seen=? WHERE id=?`,
		hostname, version, time.Now().Format(time.RFC3339), id)
	return err
}

func (s *Store) UsedPorts() (map[int]bool, error) {
	rows, err := s.db.Query(`SELECT relay_port FROM servers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := make(map[int]bool)
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		used[p] = true
	}
	return used, rows.Err()
}

func (s *Store) Log(serverID int64, user, kind, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log(ts, server_id, kind, detail, user) VALUES(?,?,?,?,?)`,
		time.Now().Format(time.RFC3339), serverID, kind, detail, user)
	return err
}

func (s *Store) ListLogs(serverID int64, limit int) ([]LogRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, server_id, kind, detail, user FROM audit_log WHERE server_id=? ORDER BY id DESC LIMIT ?`,
		serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogRecord
	for rows.Next() {
		var l LogRecord
		if err := rows.Scan(&l.ID, &l.TS, &l.ServerID, &l.Kind, &l.Detail, &l.User); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ---- users / sessions ----

func (s *Store) CreateUser(username, passwordHash, role string) (UserRecord, error) {
	now := time.Now().Format(time.RFC3339)
	res, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)`,
		username, passwordHash, role, now)
	if err != nil {
		return UserRecord{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetUser(id)
}

func scanUser(row *sql.Row) (UserRecord, error) {
	var u UserRecord
	var enabled int
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &enabled, &u.CreatedAt)
	if err != nil {
		return UserRecord{}, err
	}
	u.Enabled = enabled != 0
	return u, nil
}

func (s *Store) GetUser(id int64) (UserRecord, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, role, enabled, created_at FROM users WHERE id=?`, id))
}

func (s *Store) GetUserByName(username string) (UserRecord, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, role, enabled, created_at FROM users WHERE username=?`, username))
}

func (s *Store) ListUsers() ([]UserRecord, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, role, enabled, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRecord
	for rows.Next() {
		var u UserRecord
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &enabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUser(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM user_keys WHERE user_id=?`, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) SetUserEnabled(id int64, on bool) error {
	_, err := s.db.Exec(`UPDATE users SET enabled=? WHERE id=?`, boolToInt(on), id)
	return err
}

func (s *Store) SetUserRole(id int64, role string) error {
	_, err := s.db.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}

func (s *Store) SetPasswordHash(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return err
}

func (s *Store) AddUserKey(userID int64, publicKey, comment string) (UserKey, error) {
	res, err := s.db.Exec(
		`INSERT INTO user_keys(user_id, public_key, comment) VALUES(?,?,?)`,
		userID, publicKey, comment)
	if err != nil {
		return UserKey{}, err
	}
	id, _ := res.LastInsertId()
	var k UserKey
	err = s.db.QueryRow(
		`SELECT id, user_id, public_key, comment FROM user_keys WHERE id=?`, id).
		Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Comment)
	return k, err
}

func (s *Store) ListUserKeys(userID int64) ([]UserKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, public_key, comment FROM user_keys WHERE user_id=? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserKey
	for rows.Next() {
		var k UserKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Comment); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUserKey(id int64) error {
	_, err := s.db.Exec(`DELETE FROM user_keys WHERE id=?`, id)
	return err
}

// AllUserKeys returns every registered public key (for agent key registry).
func (s *Store) AllUserKeys() ([]UserKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, public_key, comment FROM user_keys ORDER BY user_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserKey
	for rows.Next() {
		var k UserKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Comment); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) CreateSession(token string, userID int64, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES(?,?,?,?)`,
		token, userID, expiresAt.Format(time.RFC3339), time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) GetSession(token string) (UserRecord, error) {
	var u UserRecord
	var enabled int
	var expiresAt string
	err := s.db.QueryRow(
		`SELECT u.id, u.username, u.password_hash, u.role, u.enabled, u.created_at, s.expires_at
		 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?`, token).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &enabled, &u.CreatedAt, &expiresAt)
	if err != nil {
		return UserRecord{}, err
	}
	u.Enabled = enabled != 0
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(exp) {
		return UserRecord{}, sql.ErrNoRows
	}
	return u, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
