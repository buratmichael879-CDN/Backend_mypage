package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"
)

var (
	// Direkt aus der Umgebung oder Standardwerte setzen
	API_ENC_KEY_RAW    = os.Getenv("API_ENC_KEY_RAW") // z.B. ZzRtU0x2T0t2c1pUc1R3c3F6WkdQd2lGWFp3dXlYV3U=
	ADMIN_TOKEN        = os.Getenv("ADMIN_TOKEN")     // z.B. supersecureadmintoken123
	JS_ACCESS_KEY      = os.Getenv("JS_ACCESS_KEY")   // z.B. jsaccesstoken123
	VIRUSTOTAL_API_KEY = os.Getenv("VIRUSTOTAL_API_KEY")
	PORT               = getEnv("PORT", "8080")       // Port-Nummer
	SCAN_DIR           = getEnv("SCAN_DIR", "./scandir")
	QUARANTINE_DIR     = getEnv("QUARANTINE_DIR", "./quarantine")
	PUBLIC_DIR         = getEnv("PUBLIC_DIR", "./public")
	FULLSCAN_INTERVAL  = 5 * time.Minute
	NETSCAN_INTERVAL   = 1 * time.Minute
	ALLOWED_SCRIPT_HOSTS = []string{
		"raw.githubusercontent.com",
	}
)

// Helfer-Funktion um Umgebungsvariablen mit Standardwerten zu laden
func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ServerStore für Verfolgung von IPs und Dateien
type ServerStore struct {
	mu         sync.RWMutex
	scanned    map[string]time.Time
	quarant    map[string]time.Time
	blockedIPs map[string]time.Time
}

func NewStore() *ServerStore {
	return &ServerStore{
		scanned:    make(map[string]time.Time),
		quarant:    make(map[string]time.Time),
		blockedIPs: make(map[string]time.Time),
	}
}

// Netzwerküberwachung (Monitor IPs und Ports)
func monitorNetwork(store *ServerStore) {
	log.Println("[netmon] started")
	for {
		checkNetworkOnce(store)
		time.Sleep(NETSCAN_INTERVAL)
	}
}

func checkNetworkOnce(store *ServerStore) {
	var out []byte
	var err error
	if _, e := exec.LookPath("ss"); e == nil {
		out, err = exec.Command("ss", "-tunp").CombinedOutput()
	} else if _, e := exec.LookPath("netstat"); e == nil {
		out, err = exec.Command("netstat", "-ntu").CombinedOutput()
	} else {
		log.Println("[netmon] ss/netstat not found")
		return
	}
	if err != nil {
		log.Printf("[netmon] scan error: %v", err)
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.Contains(f, ":") {
				host := strings.Split(f, ":")[0]
				host = strings.Trim(host, "[]")
				if host != "" && netIsIP(host) {
					if name, ok := suspiciousIPs[host]; ok {
						log.Printf("[netmon] suspicious ip %s: %s", host, name)
						store.mu.Lock()
						store.blockedIPs[host] = time.Now()
						store.mu.Unlock()
						tryBlockIP(host)
					}
				}
			}
		}
	}
}

func netIsIP(s string) bool {
	return net.ParseIP(s) != nil
}

func tryBlockIP(ip string) {
	if _, err := exec.LookPath("iptables"); err != nil {
		log.Printf("[netmon] cannot ipblock %s (iptables not found)", ip)
		return
	}
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[netmon] iptables failed %s: %v -- %s", ip, err, string(out))
	} else {
		log.Printf("[netmon] iptables DROP %s", ip)
	}
}

// WLAN Leak Detection (Überwachung des WLAN-Netzwerks)
func monitorWLANLeaks(store *ServerStore) {
	log.Println("[wlanmon] started")
	for {
		checkWLANLeaks()
		time.Sleep(NETSCAN_INTERVAL)
	}
}

func checkWLANLeaks() {
	cmd := exec.Command("iwconfig")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[wlanmon] error checking WLAN: %v", err)
		return
	}

	// Beispiel: Prüfen, ob die aktuelle WLAN-Verbindung zu einem nicht autorisierten Netzwerk gehört
	if strings.Contains(string(output), "untrusted_network_name") {
		log.Printf("[wlanmon] suspicious WLAN network detected")
		// Hier könntest du dann Maßnahmen wie das Trennen der Verbindung oder Blockieren der IP ergreifen
	}
}

// ---------------- AES ----------------
func parseKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, fmt.Errorf("API_ENC_KEY not set")
	}
	if kb, err := base64.StdEncoding.DecodeString(raw); err == nil && len(kb) == 32 {
		return kb, nil
	}
	if kb, err := hex.DecodeString(raw); err == nil && len(kb) == 32 {
		return kb, nil
	}
	return nil, fmt.Errorf("API_ENC_KEY must be 32 bytes (base64 or hex)")
}

func encryptAESGCM(key, plaintext []byte) (nonceB64, cipherB64 string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ciphertext), nil
}

// ---------------- MAIN ----------------
func main() {
	if API_ENC_KEY_RAW == "" {
		API_ENC_KEY_RAW = "ZzRtU0x2T0t2c1pUc1R3c3F6WkdQd2lGWFp3dXlYV3U="
	}
	if ADMIN_TOKEN == "" {
		ADMIN_TOKEN = "supersecureadmintoken123"
	}
	if JS_ACCESS_KEY == "" {
		JS_ACCESS_KEY = "jsaccesstoken123"
	}
	for _, d := range []string{SCAN_DIR, QUARANTINE_DIR, PUBLIC_DIR} {
		if err := ensureDir(d); err != nil {
			log.Fatalf("failed to ensure dir %s: %v", d, err)
		}
	}
	encKey, err := parseKey(API_ENC_KEY_RAW)
	if err != nil {
		log.Fatalf("invalid API_ENC_KEY: %v", err)
	}
	store := NewStore()
	go monitorNetwork(store)
	go monitorWLANLeaks(store)
	mux := http.NewServeMux()
	mux.Handle("/api/users/", usersHandler(store, encKey))
	mux.HandleFunc("/scripts/", scriptsHandler(store))
	mux.HandleFunc("/script/2", script2Handler(store))
	mux.HandleFunc("/", serveIndexHandler())
	log.Printf("ISO27001-luftdichter Server running on http://localhost:%s", PORT)
	if err := http.ListenAndServe(":"+PORT, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
