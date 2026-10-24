// Package tor talks to a local Tor daemon over its control port.
//
// Only two operations are needed by the platform: rotate circuits (SIGNAL
// NEWNYM) and pin exit countries (SETCONF ExitNodes). Both are process-wide in
// Tor — a NEWNYM rotates every circuit of that daemon, not just one agent's.
package tor

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Client is a control-port client. CookiePath is read at call time so a
// restarted daemon with a new cookie keeps working.
type Client struct {
	Addr       string // host:port, e.g. 127.0.0.1:9051
	CookiePath string // e.g. /var/lib/tor/control_auth_cookie
	Timeout    time.Duration
}

// NewNym asks Tor to dirty all current circuits. Tor rate-limits this to once
// per 10 seconds; a faster call is accepted but has no additional effect.
func (c *Client) NewNym(ctx context.Context) error {
	reply, err := c.do(ctx, "SIGNAL NEWNYM")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "250") {
		return fmt.Errorf("tor: SIGNAL NEWNYM -> %s", reply)
	}
	return nil
}

// SignalReload asks Tor to re-read its configuration. Client-authorization
// changes only take effect after this (or a restart).
func (c *Client) SignalReload(ctx context.Context) error {
	reply, err := c.do(ctx, "SIGNAL RELOAD")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "250") {
		return fmt.Errorf("tor: SIGNAL RELOAD -> %s", reply)
	}
	return nil
}

// Shutdown asks the daemon to exit cleanly (SIGNAL SHUTDOWN). Used for daemons
// we adopted rather than spawned, where we cannot send OS signals.
func (c *Client) Shutdown(ctx context.Context) error {
	reply, err := c.do(ctx, "SIGNAL SHUTDOWN")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "250") {
		return fmt.Errorf("tor: SIGNAL SHUTDOWN -> %s", reply)
	}
	return nil
}

// ConfigFile reports the torrc the daemon actually loaded (GETINFO config-file),
// which lets the pool recognise its own previous daemons after a restart.
func (c *Client) ConfigFile(ctx context.Context) (string, error) {
	reply, err := c.GetInfo(ctx, "config-file")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(reply, "\n") {
		// Data lines arrive as "250-config-file=/path"; the terminator is "250 OK".
		line = strings.TrimSpace(line)
		for _, pfx := range []string{"250-", "250+", "250 "} {
			line = strings.TrimPrefix(line, pfx)
		}
		if strings.HasPrefix(line, "config-file=") {
			return strings.Trim(strings.TrimPrefix(line, "config-file="), "\""), nil
		}
	}
	return "", fmt.Errorf("tor: config-file not found in reply: %s", reply)
}

// SetExitCountry pins exits to a country code (e.g. "sg"); empty clears it.
func (c *Client) SetExitCountry(ctx context.Context, cc string) error {
	cc = strings.ToLower(strings.TrimSpace(cc))
	var cmd string
	if cc == "" {
		cmd = "SETCONF ExitNodes StrictNodes=0"
	} else {
		cmd = fmt.Sprintf("SETCONF ExitNodes={%s} StrictNodes=1", cc)
	}
	reply, err := c.do(ctx, cmd)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "250") {
		return fmt.Errorf("tor: %s -> %s", cmd, reply)
	}
	return nil
}

// GetInfo sends GETINFO <key> and returns the raw reply payload (the multi-line
// body without the leading "250-" markers). Used for readiness checks
// (status/bootstrap-phase) and circuit inspection.
func (c *Client) GetInfo(ctx context.Context, key string) (string, error) {
	reply, err := c.do(ctx, "GETINFO "+key)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(reply, "250") {
		return reply, fmt.Errorf("tor: GETINFO %s -> %s", key, reply)
	}
	return reply, nil
}

// BootstrapProgress parses GETINFO status/bootstrap-phase. Tor's SOCKS port
// accepts connections long before it can build circuits, so this — not a TCP
// dial — is the honest readiness signal.
func (c *Client) BootstrapProgress(ctx context.Context) (int, string, error) {
	reply, err := c.GetInfo(ctx, "status/bootstrap-phase")
	if err != nil {
		return 0, "", err
	}
	// Example: 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
	pct := -1
	tag := ""
	for _, f := range strings.Fields(reply) {
		if strings.HasPrefix(f, "PROGRESS=") {
			fmt.Sscanf(f[len("PROGRESS="):], "%d", &pct)
		}
		if strings.HasPrefix(f, "TAG=") {
			tag = strings.Trim(f[len("TAG="):], "\"")
		}
	}
	if pct < 0 {
		return 0, tag, fmt.Errorf("tor: bootstrap phase unparsable: %s", reply)
	}
	return pct, tag, nil
}

// do opens the control connection, authenticates with the cookie file and sends
// one command. Each command gets its own connection: the control protocol is
// line-oriented, and reusing one would need asynchronous reply handling for no
// benefit at this call rate.
func (c *Client) do(ctx context.Context, cmd string) (string, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return "", fmt.Errorf("tor: dial control port: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(conn)
	if _, err := conn.Write([]byte("AUTHENTICATE " + c.cookieHex() + "\r\n")); err != nil {
		return "", err
	}
	auth, err := readReply(br)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(auth, "250") {
		return "", fmt.Errorf("tor: authenticate -> %s", auth)
	}
	if _, err := conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return readReplyAll(br)
}

// cookieHex returns the hex-encoded control cookie, or an empty string when no
// cookie file is configured (Tor then falls back to whatever auth method it has).
func (c *Client) cookieHex() string {
	if c.CookiePath == "" {
		return ""
	}
	b, err := os.ReadFile(c.CookiePath)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// readReply reads one complete control reply and returns every line joined by
// "\n". Tor's data replies are multi-line ("250-status/..." then "250 OK"), and
// GETINFO callers need the payload lines, not just the terminator.
func readReply(br *bufio.Reader) (string, error) {
	return readReplyAll(br)
}

func readReplyAll(br *bufio.Reader) (string, error) {
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if len(lines) > 0 {
				return strings.Join(lines, "\n"), nil
			}
			return "", err
		}
		cur := strings.TrimRight(line, "\r\n")
		lines = append(lines, cur)
		if len(cur) >= 4 && cur[3] == ' ' {
			return strings.Join(lines, "\n"), nil
		}
		if len(cur) >= 3 && (cur[0] == '4' || cur[0] == '5') {
			return strings.Join(lines, "\n"), nil
		}
	}
}
