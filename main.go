package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"text/template"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const slugAlphabet = "123456789abcdefghijkmnopqrstuvwxyz"

var (
	hostname      = getEnv("TUNNEL_HOSTNAME", "tunnelmonster.com")
	caddyHostname = getEnv("TUNNEL_CADDY_HOSTNAME", "localhost")
	wgName        = getWgName()
	wgNetwork     = getWgNetwork()
	wgPort        = getWgPort()
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getWgName() string {
	name := getEnv("TUNNEL_WG_INTERFACE_NAME", "tunnel")
	if len(name) > 15 {
		log.Fatalf("Wireguard interface name %q is too long (>15 chars). Override by setting TUNNEL_WG_INTERFACE_NAME", name)
	}
	return name
}

func getWgNetwork() *net.IPNet {
	networkStr := getEnv("TUNNEL_WG_NETWORK", "10.101.0.0/16")
	_, network, err := net.ParseCIDR(networkStr)
	if err != nil {
		log.Fatalf("Invalid WG network %q: %v", networkStr, err)
	}
	return network
}

func getWgPort() int {
	portStr := getEnv("TUNNEL_WG_PORT", "54321")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid WG port %q: %v", portStr, err)
	}
	return port
}

func genPrivateWgKey() ([32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return key, fmt.Errorf("failed to generate wireguard key: %w", err)
	}
	return key, nil
}

func genPublicWgKey(privateKey [32]byte) [32]byte {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return publicKey
}

func base64ToKey(keyStr string) ([32]byte, error) {
	var key [32]byte
	decoded, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return key, err
	}
	if len(decoded) != 32 {
		return key, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}

func keyToBase64(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

type Client struct {
	IP         net.IP
	Port       int
	Hostname   string
	Slug       string
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func NewClient(vpnIP net.IP, port int, hostname, slug string) (*Client, error) {
	log.Println("Generating client private key")
	privateKey, err := genPrivateWgKey()
	if err != nil {
		return nil, err
	}

	log.Println("Generating client public key")
	publicKey := genPublicWgKey(privateKey)

	client := &Client{
		IP:         vpnIP,
		Port:       port,
		Hostname:   hostname,
		Slug:       slug,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	// Route will be added after the interface is properly configured
	return client, nil
}

func (c *Client) Config(serverHostname string, serverIP net.IP, serverWgPort int, serverWgPublicKey [32]byte) string {
	tmpl := `[Interface]
Address = {{.IP}}/32
PrivateKey = {{.PrivateKey}}
PostUp = iptables -I INPUT -i %i -m tcp -p tcp --dport {{.Port}} -j ACCEPT; printf 'You can now access http://0.0.0.0:{{.Port}} on https://{{.Slug}}.{{.Hostname}}/'

[Peer]
PublicKey = {{.ServerPublicKey}}
AllowedIPs = {{.ServerIP}}/32
Endpoint = {{.ServerHostname}}:{{.ServerPort}}
PersistentKeepalive = 21
`

	t := template.Must(template.New("config").Parse(tmpl))
	var buf bytes.Buffer

	data := struct {
		*Client
		ServerHostname  string
		ServerIP        net.IP
		ServerPort      int
		ServerPublicKey string
		PrivateKey      string
	}{
		Client:          c,
		ServerHostname:  serverHostname,
		ServerIP:        serverIP,
		ServerPort:      serverWgPort,
		ServerPublicKey: keyToBase64(serverWgPublicKey),
		PrivateKey:      keyToBase64(c.PrivateKey),
	}

	t.Execute(&buf, data)
	return buf.String()
}

func (c *Client) ServerSideConfig() string {
	return fmt.Sprintf(`[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, keyToBase64(c.PublicKey), c.IP.String())
}

func (c *Client) updateRouteRules(interfaceName string) error {
	log.Printf("Adding route: ip route add %s/32 dev %s", c.IP.String(), interfaceName)
	cmd := exec.Command("ip", "route", "add", c.IP.String()+"/32", "dev", interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update routing rules for %s: %w", c.IP, err)
	}
	return nil
}

type WireguardServerInterface struct {
	Name       string
	Network    *net.IPNet
	Port       int
	Peers      []*Client
	PrivateKey [32]byte
	PublicKey  [32]byte
	IP         net.IP
	nextIPIdx  int
	device     *device.Device
	tunDevice  tun.Device
}

func NewWireguardServerInterface(name string, network *net.IPNet, port int) (*WireguardServerInterface, error) {
	privateKey, err := genPrivateWgKey()
	if err != nil {
		return nil, err
	}

	publicKey := genPublicWgKey(privateKey)

	wg := &WireguardServerInterface{
		Name:       name,
		Network:    network,
		Port:       port,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		nextIPIdx:  1, // Start from .1
	}

	wg.IP = wg.NextIP()

	if err := wg.createInterface(); err != nil {
		return nil, err
	}

	return wg, nil
}

func (w *WireguardServerInterface) NextIP() net.IP {
	ip := make(net.IP, len(w.Network.IP))
	copy(ip, w.Network.IP)

	// Convert to 4-byte representation
	if len(ip) == 16 && ip.To4() != nil {
		ip = ip.To4()
	}

	// Add the offset
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i] += byte(w.nextIPIdx >> (8 * (len(ip) - 1 - i)))
		if ip[i] != 0 {
			break
		}
	}

	w.nextIPIdx++
	return ip
}

func (w *WireguardServerInterface) AddPeer(peer *Client) {
	w.Peers = append(w.Peers, peer)
}

func (w *WireguardServerInterface) createInterface() error {
	// Create TUN device
	log.Printf("Creating TUN device: %s", w.Name)
	tunDevice, err := tun.CreateTUN(w.Name, 1420)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	w.tunDevice = tunDevice

	// Create logger
	logger := device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("(%s) ", w.Name))

	// Create WireGuard device
	w.device = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Configure the device
	config := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(w.PrivateKey[:]), w.Port)
	log.Printf("Configuring WireGuard device with port %d", w.Port)
	if err := w.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	// Bring device up
	log.Printf("Bringing WireGuard device up")
	if err := w.device.Up(); err != nil {
		return fmt.Errorf("failed to bring device up: %w", err)
	}

	// Configure IP address on the interface
	log.Printf("Setting IP address %s/32 on device %s", w.IP.String(), w.Name)
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/32", w.IP.String()), "dev", w.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %w", err)
	}

	// Bring the interface up
	log.Printf("Bringing interface %s up", w.Name)
	cmd = exec.Command("ip", "link", "set", "up", "dev", w.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

func (w *WireguardServerInterface) Down() error {
	if w.device != nil {
		w.device.Close()
	}
	if w.tunDevice != nil {
		w.tunDevice.Close()
	}
	return nil
}

func (w *WireguardServerInterface) addPeerToInterface(peer *Client) error {
	// Add peer using IPC
	log.Printf("Adding peer %s with allowed IP %s/32", hex.EncodeToString(peer.PublicKey[:])[:8], peer.IP.String())
	config := fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", hex.EncodeToString(peer.PublicKey[:]), peer.IP.String())
	if err := w.device.IpcSet(config); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	// Add route for the peer
	log.Printf("Adding route for peer IP %s", peer.IP.String())
	if err := peer.updateRouteRules(w.Name); err != nil {
		return fmt.Errorf("failed to add route for peer: %w", err)
	}

	log.Println("Peers are now: ", w.Peers)
	for _, v := range w.Peers {
		log.Println(v.Hostname, v.IP, keyToBase64(v.PrivateKey), keyToBase64(v.PublicKey))
	}

	return nil
}

func (w *WireguardServerInterface) ReloadInterface() error {
	// Add the most recently added peer to the interface
	if len(w.Peers) > 0 {
		lastPeer := w.Peers[len(w.Peers)-1]
		if err := w.addPeerToInterface(lastPeer); err != nil {
			return err
		}
	}
	return nil
}

func initReverseProxy(caddyHostname string) error {
	payload := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{":80"},
						"routes": []interface{}{},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("http://%s:2019/load", caddyHostname), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to initialize reverse proxy: %s", resp.Status)
	}

	return nil
}

func updateReverseProxy(serverHostname, caddyHostname string, client *Client) error {
	payload := map[string]interface{}{
		"handle": []interface{}{
			map[string]interface{}{
				"handler": "subroute",
				"routes": []interface{}{
					map[string]interface{}{
						"handle": []interface{}{
							map[string]interface{}{
								"handler": "reverse_proxy",
								"upstreams": []interface{}{
									map[string]string{
										"dial": fmt.Sprintf("%s:%d", client.IP.String(), client.Port),
									},
								},
							},
						},
					},
				},
			},
		},
		"match": []interface{}{
			map[string][]string{
				"host": {fmt.Sprintf("%s.%s", client.Slug, serverHostname)},
			},
		},
		"terminal": true,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(
		fmt.Sprintf("http://%s:2019/config/apps/http/servers/srv0/routes/", caddyHostname),
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update reverse proxy: %s", resp.Status)
	}

	log.Println("Caddy configuration updated successfully!")

	return nil
}

func makeSlug(alphabet string, length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = alphabet[mathrand.Intn(len(alphabet))]
	}
	return string(result)
}

var wg *WireguardServerInterface

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Try to find the static files in multiple locations
	staticPaths := []string{
		"static/index.html",
		os.Getenv("TUNNEL_STATIC_PATH") + "/index.html",
	}

	var tmpl *template.Template
	var err error

	for _, path := range staticPaths {
		if path == "/index.html" { // Skip empty env var
			continue
		}
		if _, statErr := os.Stat(path); statErr == nil {
			tmpl, err = template.ParseFiles(path)
			if err == nil {
				break
			}
		}
	}

	if tmpl == nil {
		log.Printf("Failed to find index template in any of: %v", staticPaths)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Template data with configuration values
	data := struct {
		Hostname string
		ServerIP string
	}{
		Hostname: hostname,
		ServerIP: wg.IP.String(),
	}

	// Set content type and execute template
	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Failed to execute template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func newTunnelHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	portStr := vars["port"]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}

	slug := makeSlug(slugAlphabet, 6)

	client, err := NewClient(wg.NextIP(), port, hostname, slug)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		http.Error(w, "Failed to create tunnel", http.StatusInternalServerError)
		return
	}

	wg.AddPeer(client)

	if err := wg.ReloadInterface(); err != nil {
		log.Printf("Failed to reload interface: %v", err)
		http.Error(w, "Failed to configure tunnel", http.StatusInternalServerError)
		return
	}

	if err := updateReverseProxy(hostname, caddyHostname, client); err != nil {
		log.Printf("Failed to update reverse proxy: %v", err)
		http.Error(w, "Failed to configure proxy", http.StatusInternalServerError)
		return
	}

	config := client.Config(hostname, wg.IP, wg.Port, wg.PublicKey)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(config))
}

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	flag.Parse()

	mathrand.Seed(time.Now().UnixNano())

	var err error
	wg, err = NewWireguardServerInterface(wgName, wgNetwork, wgPort)
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard interface: %v", err)
	}

	defer func() {
		if err := wg.Down(); err != nil {
			log.Printf("Failed to bring down WireGuard interface: %v", err)
		}
	}()

	if err := initReverseProxy(caddyHostname); err != nil {
		log.Fatalf("Failed to initialize reverse proxy: %v", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", indexHandler).Methods("GET")
	r.HandleFunc("/{port:[0-9]+}", newTunnelHandler).Methods("GET")

	log.Printf("Starting server on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, r))
}
