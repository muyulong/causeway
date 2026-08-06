package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"causeway/internal/tunnel"
)

type APIConfig struct {
	Store        *Store
	Registry     *Registry
	WebToken     string
	RelayAddr    string // host:port agents dial for the tunnel
	WebBase      string // http://host:port of the web UI
	AgentBinary  string
	CAPath       string
	WebSSHKey    string
	WebSSHKeyPub string
}

type API struct {
	cfg APIConfig
}

func NewAPI(cfg APIConfig) *API {
	return &API{cfg: cfg}
}

type ctxUserKey struct{}

func withUserCtx(r *http.Request, username, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, [2]string{username, role}))
}

// userOf returns the authenticated username (or "?" if unknown).
func userOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUserKey{}).([2]string); ok {
		return v[0]
	}
	return "?"
}

func roleOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUserKey{}).([2]string); ok {
		return v[1]
	}
	return ""
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.auth(a.handleLogout))
	mux.HandleFunc("GET /api/me", a.auth(a.handleMe))
	mux.HandleFunc("GET /api/users", a.admin(a.handleListUsers))
	mux.HandleFunc("POST /api/users", a.admin(a.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", a.admin(a.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", a.admin(a.handleDeleteUser))
	mux.HandleFunc("GET /api/users/{id}/keys", a.admin(a.handleListUserKeys))
	mux.HandleFunc("POST /api/users/{id}/keys", a.admin(a.handleAddUserKey))
	mux.HandleFunc("DELETE /api/users/{id}/keys/{keyid}", a.admin(a.handleDeleteUserKey))
	mux.HandleFunc("GET /api/servers", a.auth(a.handleList))
	mux.HandleFunc("POST /api/servers", a.auth(a.handleCreate))
	mux.HandleFunc("DELETE /api/servers/{id}", a.auth(a.handleDelete))
	mux.HandleFunc("PUT /api/servers/{id}", a.auth(a.handleUpdate))
	mux.HandleFunc("POST /api/servers/{id}/reconnect", a.auth(a.handleReconnect))
	mux.HandleFunc("POST /api/servers/{id}/upgrade", a.auth(a.handleUpgrade))
	mux.HandleFunc("GET /api/servers/{id}/install", a.auth(a.handleInstall))
	mux.HandleFunc("GET /api/servers/{id}/logs", a.auth(a.handleLogs))
	mux.HandleFunc("GET /api/servers/{id}/users", a.auth(a.handleServerUsers))
	mux.HandleFunc("GET /ws/terminal/{id}", a.handleTerminal)
	mux.HandleFunc("GET /download/agent", a.handleDownloadAgent)
	mux.HandleFunc("GET /download/agent.sha256", a.handleAgentSHA256)
	mux.HandleFunc("GET /download/ca", a.handleDownloadCA)
	mux.HandleFunc("GET /download/webkey", a.handleDownloadWebKey)
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("embed static: %v", err)
	}
	staticHandler := http.FileServer(http.FS(sub))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 禁止缓存前端文件，避免浏览器一直跑旧版 JS
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		staticHandler.ServeHTTP(w, r)
	}))
	return mux
}

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if constantTimeEqual(token, a.cfg.WebToken) {
			// 平台 token：视为管理员（引导/兜底）
			next(w, withUserCtx(r, "admin", "admin"))
			return
		}
		if u, err := a.cfg.Store.GetSession(token); err == nil && u.Enabled {
			next(w, withUserCtx(r, u.Username, u.Role))
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
	}
}

func (a *API) admin(next http.HandlerFunc) http.HandlerFunc {
	return a.auth(func(w http.ResponseWriter, r *http.Request) {
		if roleOf(r) != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		next(w, r)
	})
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	u, err := a.cfg.Store.GetUserByName(req.Username)
	if err != nil || !u.Enabled || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "用户名或密码错误"})
		return
	}
	token := randomToken()
	if err := a.cfg.Store.CreateSession(token, u.ID, time.Now().Add(7*24*time.Hour)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "username": u.Username, "role": u.Role,
	})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	_ = a.cfg.Store.DeleteSession(token)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"username": userOf(r), "role": roleOf(r),
	})
}

func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.cfg.Store.ListUsers()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, a.userJSON(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "用户名不能为空，密码至少 8 位"})
		return
	}
	if req.Role != "admin" && req.Role != "member" {
		req.Role = "member"
	}
	if _, err := a.cfg.Store.GetUserByName(req.Username); err == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "用户名已存在"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	u, err := a.cfg.Store.CreateUser(req.Username, string(hash), req.Role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": a.userJSON(u)})
}

func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Enabled  *bool   `json:"enabled"`
		Password *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	if req.Role != nil && (*req.Role == "admin" || *req.Role == "member") {
		_ = a.cfg.Store.SetUserRole(id, *req.Role)
	}
	if req.Enabled != nil {
		_ = a.cfg.Store.SetUserEnabled(id, *req.Enabled)
	}
	if req.Password != nil && len(*req.Password) >= 8 {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err == nil {
			_ = a.cfg.Store.SetPasswordHash(id, string(hash))
		}
	}
	u, _ = a.cfg.Store.GetUser(id)
	writeJSON(w, http.StatusOK, map[string]any{"user": a.userJSON(u)})
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if userOf(r) != "admin" {
		u, err := a.cfg.Store.GetUser(id)
		if err == nil && u.Username == userOf(r) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不能删除自己"})
			return
		}
	}
	if err := a.cfg.Store.DeleteUser(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) handleListUserKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	keys, err := a.cfg.Store.ListUserKeys(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (a *API) handleAddUserKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
		Comment   string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "公钥格式不正确"})
		return
	}
	line := string(bytes.TrimSpace([]byte(req.PublicKey)))
	k, err := a.cfg.Store.AddUserKey(id, line, req.Comment)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "公钥已存在或保存失败: " + err.Error()})
		return
	}
	_ = pub
	writeJSON(w, http.StatusCreated, map[string]any{"key": k})
}

func (a *API) handleDeleteUserKey(w http.ResponseWriter, r *http.Request) {
	keyid, err := strconv.ParseInt(r.PathValue("keyid"), 10, 64)
	if err != nil || keyid <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad key id"})
		return
	}
	if err := a.cfg.Store.DeleteUserKey(keyid); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) handleList(w http.ResponseWriter, r *http.Request) {
	recs, err := a.cfg.Store.ListServers()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, a.serverJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func (a *API) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !nameRe.MatchString(req.Name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name must match [a-zA-Z0-9._-]{1,64}"})
		return
	}
	if _, err := a.cfg.Store.GetServerByName(req.Name); err == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "server already exists"})
		return
	}
	port := a.cfg.Registry.NextFreePort()
	token := randomToken()
	rec, err := a.cfg.Store.CreateServer(req.Name, token, port)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = a.cfg.Store.Log(rec.ID, userOf(r), "server_created", "name="+req.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"server":  a.serverJSON(rec),
		"token":   token,
		"install": a.installScript(rec.Name, token),
	})
}

func (a *API) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	a.cfg.Registry.CloseByName(rec.Name)
	_ = a.cfg.Store.Log(id, userOf(r), "server_deleted", "name="+rec.Name)
	if err := a.cfg.Store.DeleteServer(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	var req struct {
		AdminEnabled *bool   `json:"admin_enabled"`
		ProxyEnabled *bool   `json:"proxy_enabled"`
		DefaultUser  *string `json:"default_user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	if req.AdminEnabled != nil {
		if err := a.cfg.Store.SetAdminEnabled(id, *req.AdminEnabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		if !*req.AdminEnabled {
			a.cfg.Registry.CloseByName(rec.Name)
		}
		_ = a.cfg.Store.Log(id, userOf(r), "admin_toggle", fmt.Sprintf("enabled=%v", *req.AdminEnabled))
	}
	if req.ProxyEnabled != nil {
		if err := a.cfg.Store.SetProxyEnabled(id, *req.ProxyEnabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		_ = a.cfg.Store.Log(id, userOf(r), "proxy_toggle", fmt.Sprintf("enabled=%v", *req.ProxyEnabled))
	}
	if req.DefaultUser != nil {
		if err := a.cfg.Store.SetDefaultUser(id, *req.DefaultUser); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		_ = a.cfg.Store.Log(id, userOf(r), "default_user", "user="+*req.DefaultUser)
		a.pushAgentConfigs()
	}
	rec, _ = a.cfg.Store.GetServer(id)
	writeJSON(w, http.StatusOK, map[string]any{"server": a.serverJSON(rec)})
}

// handleServerUsers lists OS user accounts on the target machine.
func (a *API) handleServerUsers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if !a.cfg.Registry.Online(rec.Name) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "agent offline"})
		return
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rec.RelayPort))
	client, session, err := dialSSH(a.cfg.WebSSHKey, addr)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "无法连接 agent: " + err.Error()})
		return
	}
	defer client.Close()
	out, err := session.CombinedOutput("__relay_list_users")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "获取用户列表失败: " + err.Error(), "output": string(out)})
		return
	}
	var users []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &users); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "解析用户列表失败: " + err.Error(), "output": string(out)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "default_user": rec.DefaultUser})
}

func (a *API) handleReconnect(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	a.cfg.Registry.CloseByName(rec.Name)
	_ = a.cfg.Store.Log(id, userOf(r), "reconnect_requested", "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if !a.cfg.Registry.Online(rec.Name) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "agent offline"})
		return
	}
	if a.cfg.AgentBinary == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "agent-binary not configured"})
		return
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rec.RelayPort))
	client, session, err := dialSSH(a.cfg.WebSSHKey, addr)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "无法连接目标机（请确认 authorized_keys 里有 web terminal key）: " + err.Error(),
		})
		return
	}
	defer client.Close()

	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := session.CombinedOutput("__relay_upgrade " + a.upgradeScript())
		ch <- result{out, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			_ = a.cfg.Store.Log(id, userOf(r), "upgrade_failed", string(res.out))
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":  "升级脚本执行失败: " + res.err.Error(),
				"output": string(res.out),
			})
			return
		}
		_ = a.cfg.Store.Log(id, userOf(r), "upgrade", string(res.out))
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"version": tunnel.Version,
			"output":  string(res.out),
		})
	case <-time.After(90 * time.Second):
		_ = session.Close()
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{"error": "升级超时"})
	}
}

func (a *API) upgradeScript() string {
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
WEB=%q
# 从正在运行的 agent 进程 cmdline 发现真实路径和启动参数
AGENT_PID=$PPID
CMDLINE=$(tr '\0' ' ' < /proc/$AGENT_PID/cmdline)
BIN=$(echo "$CMDLINE" | awk '{print $1}')
ARGS=$(echo "$CMDLINE" | cut -d' ' -f2-)
DIR=$(dirname "$BIN")
TMP="$DIR/agent.new"
if [ -s "$DIR/agent.args" ]; then
  RESTART_ARGS=$(cat "$DIR/agent.args")
else
  CONF=$(echo "$CMDLINE" | sed -n 's/.*-config \([^ ]*\).*/\1/p')
  if [ -n "$CONF" ]; then
    RESTART_ARGS="'-config' '$CONF'"
  else
    RESTART_ARGS="$ARGS"
  fi
fi
mkdir -p "$DIR"
curl -fsSL "$WEB/download/agent" -o "$TMP"
EXPECT=$(curl -fsSL "$WEB/download/agent.sha256" | tr -dc '0-9a-fA-F')
GOT=$(sha256sum "$TMP" | tr -dc '0-9a-fA-F' | cut -c1-64)
if [ "$GOT" != "$EXPECT" ]; then
  echo "hash mismatch: got=$GOT want=$EXPECT raw=$(sha256sum "$TMP")"
  rm -f "$TMP"
  exit 1
fi
chmod +x "$TMP"
if ! "$TMP" -version >/dev/null 2>&1; then
  echo "new binary sanity check failed"
  rm -f "$TMP"
  exit 1
fi
[ -f "$BIN" ] && mv "$BIN" "$BIN.old" 2>/dev/null || true
mv "$TMP" "$BIN"
chmod +x "$BIN"
cat > "$DIR/restart.sh" <<RESTART
#!/bin/bash
sleep 1
UNIT="\$HOME/.config/systemd/user/ops-agent.service"
if [ -f "\$UNIT" ] && grep -qF "$BIN" "\$UNIT" && systemctl --user is-active ops-agent >/dev/null 2>&1; then
  systemctl --user restart ops-agent && exit 0
fi
kill "$AGENT_PID" 2>/dev/null || true
sleep 1
nohup "$BIN" $RESTART_ARGS >> "$DIR/agent.log" 2>&1 &
RESTART
chmod +x "$DIR/restart.sh"
nohup bash "$DIR/restart.sh" >/dev/null 2>&1 &
echo "upgrade complete: $GOT"
`, a.cfg.WebBase)
}

func (a *API) handleAgentSHA256(w http.ResponseWriter, r *http.Request) {
	if a.cfg.AgentBinary == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "agent-binary not configured"})
		return
	}
	b, err := os.ReadFile(a.cfg.AgentBinary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	sum := sha256.Sum256(b)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "\n"))
}

func (a *API) handleInstall(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rec, err := a.cfg.Store.GetServer(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	token := randomToken()
	if err := a.cfg.Store.SetToken(id, token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = a.cfg.Store.Log(id, userOf(r), "token_rotated", "install script generated")
	writeJSON(w, http.StatusOK, map[string]any{
		"install": a.installScript(rec.Name, token),
	})
}

func (a *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	logs, err := a.cfg.Store.ListLogs(id, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

func (a *API) handleDownloadAgent(w http.ResponseWriter, r *http.Request) {
	if a.cfg.AgentBinary == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "agent-binary not configured"})
		return
	}
	http.ServeFile(w, r, a.cfg.AgentBinary)
}

func (a *API) handleDownloadCA(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(a.cfg.CAPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "ca not found"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(b)
}

func (a *API) handleDownloadWebKey(w http.ResponseWriter, r *http.Request) {
	if a.cfg.WebSSHKeyPub == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "web key not configured"})
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(a.cfg.WebSSHKeyPub))
}

func (a *API) serverJSON(rec ServerRecord) map[string]any {
	return map[string]any{
		"id":            rec.ID,
		"name":          rec.Name,
		"port":          rec.RelayPort,
		"online":        a.cfg.Registry.Online(rec.Name),
		"proxy_enabled": rec.ProxyEnabled,
		"admin_enabled": rec.AdminEnabled,
		"default_user":  rec.DefaultUser,
		"agent_version": rec.AgentVersion,
		"hostname":      rec.Hostname,
		"last_seen":     rec.LastSeen,
		"created_at":    rec.CreatedAt,
	}
}

func (a *API) userJSON(u UserRecord) map[string]any {
	keys, _ := a.cfg.Store.ListUserKeys(u.ID)
	return map[string]any{
		"id":         u.ID,
		"username":   u.Username,
		"role":       u.Role,
		"enabled":    u.Enabled,
		"created_at": u.CreatedAt,
		"key_count":  len(keys),
	}
}

// pushAgentConfigs re-pushes the key registry + default users to all online agents.
func (a *API) pushAgentConfigs() {
	recs, err := a.cfg.Store.ListServers()
	if err != nil {
		return
	}
	for _, rec := range recs {
		if !a.cfg.Registry.Online(rec.Name) {
			continue
		}
		cfg := a.cfg.Registry.AgentConfig(rec)
		if err := a.cfg.Registry.SendControl(rec.Name, tunnel.ControlServerUpdate, cfg); err != nil {
			log.Printf("push config to %s: %v", rec.Name, err)
		}
	}
}

func (a *API) installScript(name, token string) string {
	return fmt.Sprintf(`#!/bin/bash
# 自用 SSH 平台 - Agent 安装脚本
set -euo pipefail
NAME=%q
TOKEN=%q
RELAY=%q
WEB=%q
mkdir -p ~/.ops/agent
curl -fsSL "$WEB/download/agent" -o ~/.ops/agent/agent
curl -fsSL "$WEB/download/ca" -o ~/.ops/agent/ca.pem
mkdir -p ~/.ssh
WEBKEY=$(curl -fsSL "$WEB/download/webkey")
grep -qF "$WEBKEY" ~/.ssh/authorized_keys 2>/dev/null || echo "$WEBKEY" >> ~/.ssh/authorized_keys
chmod +x ~/.ops/agent/agent
~/.ops/agent/agent install --server-id "$NAME" --relay "$RELAY" --ca ~/.ops/agent/ca.pem --token "$TOKEN" --data-dir ~/.ops/agent
echo "agent installed"
echo "logs: journalctl --user -u ops-agent -f"
`, name, token, a.cfg.RelayAddr, a.cfg.WebBase)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad id"})
		return 0, false
	}
	return id, true
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
