package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"

	"golang.org/x/crypto/ssh"
)

// EnsureWebTermKey creates (or loads) the workstation's SSH identity used by
// the web terminal. Its public key must be present in each target's
// authorized_keys file.
func EnsureWebTermKey(path string) (pubKey string, err error) {
	if b, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(b)
		if err == nil {
			return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	keyPEM, err := ssh.MarshalPrivateKey(priv, "ssh-relay webterm")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(keyPEM), 0o600); err != nil {
		return "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}
