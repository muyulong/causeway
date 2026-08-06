package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"causeway/internal/relay"
	"causeway/internal/tunnel"
)

func main() {
	var listen, advertise, dataDir, webListen, webToken, dbPath, agentBinary string
	var portStart int
	flag.StringVar(&listen, "listen", "0.0.0.0:9443", "relay TLS listen address")
	flag.StringVar(&advertise, "advertise", "", "address agents dial (host:port), used for cert SANs")
	flag.StringVar(&dataDir, "data-dir", "./data", "data directory (CA, certs, DB)")
	flag.StringVar(&webListen, "web-listen", "127.0.0.1:8080", "web UI listen address")
	flag.StringVar(&webToken, "web-token", "", "web UI token (auto-generated if empty)")
	flag.StringVar(&dbPath, "db", "", "sqlite database path (default DATA_DIR/relay.db)")
	flag.StringVar(&agentBinary, "agent-binary", "", "path to agent binary served for installs")
	flag.IntVar(&portStart, "port-start", 22001, "first SSH relay port")
	flag.Parse()

	if advertise == "" {
		advertise = listen
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	caCert, caKey, err := tunnel.EnsureCA(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	advertiseHost := advertise
	advertisePort := "9443"
	if h, p, err := net.SplitHostPort(advertise); err == nil {
		advertiseHost = h
		advertisePort = p
	}
	host := advertiseHost
	sans := uniqueStrings([]string{host, "127.0.0.1", "localhost"})
	certFile, keyFile, err := tunnel.EnsureServerCert(dataDir, caCert, caKey, sans)
	if err != nil {
		log.Fatal(err)
	}
	webPort := "8080"
	if _, p, err := net.SplitHostPort(webListen); err == nil {
		webPort = p
	}
	if webToken == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		webToken = hex.EncodeToString(b)
		log.Printf("generated web token: %s", webToken)
	}
	if dbPath == "" {
		dbPath = filepath.Join(dataDir, "relay.db")
	}
	store, err := relay.OpenStore(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	webKeyPath := filepath.Join(dataDir, "webterm_key")
	webPubKey, err := relay.EnsureWebTermKey(webKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("web terminal key (add to each target's authorized_keys):\n%s", webPubKey)
	reg := relay.NewRegistry(store, portStart, webPubKey)

	api := relay.NewAPI(relay.APIConfig{
		Store:        store,
		Registry:     reg,
		WebToken:     webToken,
		RelayAddr:    net.JoinHostPort(advertiseHost, advertisePort),
		WebBase:      "http://" + net.JoinHostPort(advertiseHost, webPort),
		AgentBinary:  agentBinary,
		CAPath:       caCert,
		WebSSHKey:    webKeyPath,
		WebSSHKeyPub: webPubKey,
	})
	go func() {
		log.Printf("web ui on http://%s", webListen)
		log.Fatal("web server: ", http.ListenAndServe(webListen, api.Handler()))
	}()

	tlsCfg, err := tunnel.ServerTLSConfig(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := tls.Listen("tcp", listen, tlsCfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("relay listening on %s (tls), advertise=%s", listen, advertise)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go relay.HandleAgent(conn, reg)
	}
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
