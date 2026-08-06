package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Config struct {
	Relay          string `json:"relay"`
	CA             string `json:"ca"`
	ServerID       string `json:"server_id"`
	Token          string `json:"token"`
	AuthorizedKeys string `json:"authorized_keys,omitempty"`
	DataDir        string `json:"data_dir"`
	SocksListen    string `json:"socks_listen,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func WriteConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func systemdUnit(cfg Config) string {
	bin := filepath.Join(cfg.DataDir, "agent")
	conf := filepath.Join(cfg.DataDir, "config.json")
	return `[Unit]
Description=Causeway Agent (` + cfg.ServerID + `)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + bin + ` -config ` + conf + `
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`
}

// Install writes the agent config, installs a systemd user service when
// available, and falls back to nohup + @reboot crontab otherwise.
func Install(cfg Config, forceFallback, noCron bool) error {
	if err := WriteConfig(cfgPath(cfg), cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DataDir), 0o700); err != nil {
		return err
	}
	if !forceFallback && trySystemd(cfg) {
		return nil
	}
	return fallbackStart(cfg, noCron)
}

func cfgPath(cfg Config) string {
	return filepath.Join(cfg.DataDir, "config.json")
}

func trySystemd(cfg Config) bool {
	unitDir := filepath.Join(homeDir(), ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return false
	}
	unitPath := filepath.Join(unitDir, "ops-agent.service")
	if err := os.WriteFile(unitPath, []byte(systemdUnit(cfg)), 0o644); err != nil {
		return false
	}
	if err := runCmd("systemctl", "--user", "daemon-reload"); err != nil {
		return false
	}
	if err := runCmd("systemctl", "--user", "enable", "--now", "ops-agent.service"); err != nil {
		return false
	}
	fmt.Println("installed systemd user service: ops-agent.service")
	fmt.Println("logs: journalctl --user -u ops-agent -f")
	return true
}

func fallbackStart(cfg Config, noCron bool) error {
	bin := filepath.Join(cfg.DataDir, "agent")
	args := []string{
		"-config", cfgPath(cfg),
	}
	logf, err := os.OpenFile(filepath.Join(cfg.DataDir, "agent.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command("nohup", append([]string{bin}, args...)...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	if !noCron {
		if err := ensureCronReboot(cfg.DataDir, bin, args); err != nil {
			fmt.Printf("warning: could not add @reboot entry: %v\n", err)
		}
	}
	fmt.Println("started agent via nohup (systemd unavailable)")
	if noCron {
		fmt.Println("note: no crontab @reboot entry added (-no-cron)")
	}
	return nil
}

func ensureCronReboot(dataDir, bin string, args []string) error {
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil && !strings.Contains(err.Error(), "no crontab") {
		return err
	}
	line := "@reboot sleep 5 && " + shellJoin(append([]string{bin}, args...)) + " >> " +
		filepath.Join(dataDir, "agent.log") + " 2>&1"
	lines := strings.TrimSpace(string(out))
	if strings.Contains(lines, "ops-agent") {
		return nil
	}
	content := lines + "\n" + line + "\n"
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	return cmd.Run()
}

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = ShellQuote(a)
	}
	return strings.Join(q, " ")
}

// ShellQuoteArgs shell-quotes each argument for safe reuse in shell scripts.
func ShellQuoteArgs(args []string) string {
	return shellJoin(args)
}

// ShellQuote single-quotes a string for shell use.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
