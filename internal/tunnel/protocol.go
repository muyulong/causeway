package tunnel

import "encoding/json"

const Version = "0.2.0"

const (
	ControlRegistered   = "registered"
	ControlProxyEnabled = "proxy_enabled"
	ControlReconnect    = "reconnect"
	ControlServerUpdate = "server_update"
)

type RegisterMsg struct {
	ServerID string `json:"server_id"`
	Token    string `json:"token"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}

type StreamOpenMsg struct {
	Kind string `json:"kind"` // "ssh" | "socks"
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

type ControlMsg struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

func EncodeControl(typ string, v any) ([]byte, error) {
	var data json.RawMessage
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		data = b
	}
	return json.Marshal(ControlMsg{Type: typ, Data: data})
}
