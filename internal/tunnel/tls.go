package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

// EnsureCA creates a self-signed CA in dir if it does not exist yet.
func EnsureCA(dir string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dir, "ca.pem")
	keyFile = filepath.Join(dir, "ca.key")
	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ssh-relay CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(keyFile, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

// EnsureServerCert creates the relay server certificate signed by the CA.
func EnsureServerCert(dir, caCertFile, caKeyFile string, sans []string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dir, "server.pem")
	keyFile = filepath.Join(dir, "server.key")
	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}
	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", "", errors.New("cannot parse CA certificate")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return "", "", err
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return "", "", errors.New("cannot parse CA key")
	}
	caKeyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", "", err
	}
	caKey, ok := caKeyAny.(ed25519.PrivateKey)
	if !ok {
		return "", "", errors.New("CA key is not ed25519")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ssh-relay server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(keyFile, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ClientConfig builds a TLS config that pins the relay CA.
func ClientConfig(caFile, serverName string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("cannot load CA certificate")
	}
	return &tls.Config{
		RootCAs:    roots,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}, nil
}
