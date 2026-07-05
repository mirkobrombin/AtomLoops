// Package wifi is the recovery-image wifi driver: it brings up a wireless link
// with no NetworkManager and no desktop, by talking wpa_supplicant's control
// socket directly and running udhcpc for the lease. It is the piece that makes a
// recovery usable on a laptop with no ethernet: scan, pick, associate, get an IP,
// then the recovery agent can fetch a signed image over it.
//
// The control protocol is wpa_supplicant's text ctrl_iface over a unix datagram
// socket (SCAN, SCAN_RESULTS, ADD_NETWORK, SET_NETWORK, SELECT_NETWORK, STATUS).
package wifi

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Network is one scan result.
type Network struct {
	SSID   string
	BSSID  string
	Signal int  // level in dBm as reported by wpa_supplicant
	Secure bool // true if the flags advertise WPA/WPA2/WPA3/WEP
}

// Client drives one wireless interface via its wpa_supplicant control socket.
type Client struct {
	iface    string
	ctrlPath string // e.g. /run/wpa_supplicant/wlan0
	dhcp     string // udhcpc binary
	// injectable for tests
	runDHCP func(ctx context.Context, iface string) error
}

// New builds a client for iface (e.g. "wlan0"). The wpa_supplicant control
// socket is expected at /run/wpa_supplicant/<iface>.
func New(iface string) *Client {
	c := &Client{
		iface:    iface,
		ctrlPath: filepath.Join("/run/wpa_supplicant", iface),
		dhcp:     "udhcpc",
	}
	c.runDHCP = c.udhcpc
	return c
}

// dialCtrl opens a datagram connection to the wpa_supplicant control socket. The
// client must bind its own local address for replies to come back.
func (c *Client) dialCtrl() (*net.UnixConn, func(), error) {
	local := filepath.Join(os.TempDir(), fmt.Sprintf("wpa_ctrl_%d_%d", os.Getpid(), time.Now().UnixNano()))
	laddr := &net.UnixAddr{Name: local, Net: "unixgram"}
	raddr := &net.UnixAddr{Name: c.ctrlPath, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		return nil, nil, fmt.Errorf("wifi: dial %s: %w", c.ctrlPath, err)
	}
	cleanup := func() { conn.Close(); os.Remove(local) }
	return conn, cleanup, nil
}

// cmd sends one control command and returns the reply text.
func (c *Client) cmd(conn *net.UnixConn, s string) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(s)); err != nil {
		return "", fmt.Errorf("wifi: write %q: %w", s, err)
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("wifi: read reply to %q: %w", s, err)
	}
	return string(buf[:n]), nil
}

// Scan triggers a scan, waits for it to settle, and returns the parsed results.
func (c *Client) Scan(ctx context.Context) ([]Network, error) {
	conn, cleanup, err := c.dialCtrl()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if _, err := c.cmd(conn, "SCAN"); err != nil {
		return nil, err
	}
	// wpa_supplicant needs a moment to sweep the band; poll results.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(3 * time.Second):
	}
	res, err := c.cmd(conn, "SCAN_RESULTS")
	if err != nil {
		return nil, err
	}
	return parseScanResults(res), nil
}

// parseScanResults parses the tab-separated SCAN_RESULTS table:
//
//	bssid / frequency / signal level / flags / ssid
func parseScanResults(out string) []Network {
	var nets []Network
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header row / blank
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		sig, _ := strconv.Atoi(strings.TrimSpace(f[2]))
		flags := f[3]
		nets = append(nets, Network{
			BSSID:  f[0],
			Signal: sig,
			Secure: strings.Contains(flags, "WPA") || strings.Contains(flags, "WEP"),
			SSID:   f[4],
		})
	}
	return nets
}

// Connect associates with ssid (psk empty for an open network), waits for the
// link to reach COMPLETED, then acquires a DHCP lease.
func (c *Client) Connect(ctx context.Context, ssid, psk string) error {
	conn, cleanup, err := c.dialCtrl()
	if err != nil {
		return err
	}
	defer cleanup()

	id, err := c.cmd(conn, "ADD_NETWORK")
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if _, err := strconv.Atoi(id); err != nil {
		return fmt.Errorf("wifi: ADD_NETWORK returned %q", id)
	}

	set := func(kv string) error {
		r, err := c.cmd(conn, fmt.Sprintf("SET_NETWORK %s %s", id, kv))
		if err != nil {
			return err
		}
		if !strings.HasPrefix(r, "OK") {
			return fmt.Errorf("wifi: SET_NETWORK %s: %s", kv, strings.TrimSpace(r))
		}
		return nil
	}
	if err := set(fmt.Sprintf(`ssid "%s"`, ssid)); err != nil {
		return err
	}
	if psk == "" {
		if err := set("key_mgmt NONE"); err != nil {
			return err
		}
	} else {
		if err := set(fmt.Sprintf(`psk "%s"`, psk)); err != nil {
			return err
		}
	}
	if _, err := c.cmd(conn, "SELECT_NETWORK "+id); err != nil {
		return err
	}

	if err := c.waitConnected(ctx, conn); err != nil {
		return err
	}
	return c.runDHCP(ctx, c.iface)
}

// waitConnected polls STATUS until wpa_state=COMPLETED or the context/deadline
// expires. A wrong password shows up as repeated disconnects, so we bound it.
func (c *Client) waitConnected(ctx context.Context, conn *net.UnixConn) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		st, err := c.cmd(conn, "STATUS")
		if err != nil {
			return err
		}
		if statusField(st, "wpa_state") == "COMPLETED" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wifi: association to %q timed out (wrong password or out of range?)", c.iface)
		}
		time.Sleep(time.Second)
	}
}

// statusField extracts key=value from a STATUS reply.
func statusField(status, key string) string {
	for _, line := range strings.Split(status, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
			return v
		}
	}
	return ""
}

// udhcpc runs the busybox DHCP client for one lease. -q exits once the lease is
// obtained; -f keeps it foreground until then. Note: the udhcpc default script
// must be `ip`-based, not ifconfig (which is absent) -- the recovery ships that.
func (c *Client) udhcpc(ctx context.Context, iface string) error {
	cmd := exec.CommandContext(ctx, c.dhcp, "-i", iface, "-f", "-q", "-n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wifi: dhcp on %s failed: %w (%s)", iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}
