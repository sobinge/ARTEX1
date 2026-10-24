package tor

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeControl accepts one connection, checks the command, replies 250 OK.
func fakeControl(t *testing.T, wantCmd string, got *[]string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(conn)
			line, _ := br.ReadString('\n')
			*got = append(*got, strings.TrimSpace(line))
			conn.Write([]byte("250 OK\r\n"))
			line, _ = br.ReadString('\n')
			*got = append(*got, strings.TrimSpace(line))
			conn.Write([]byte("250 OK\r\n"))
			conn.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestNewNym(t *testing.T) {
	var got []string
	addr, stop := fakeControl(t, "SIGNAL NEWNYM", &got)
	defer stop()
	c := &Client{Addr: addr, Timeout: 2 * time.Second}
	if err := c.NewNym(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 || !strings.HasPrefix(got[1], "SIGNAL NEWNYM") {
		t.Fatalf("commands = %v", got)
	}
}

func TestSetExitCountry(t *testing.T) {
	var got []string
	addr, stop := fakeControl(t, "", &got)
	defer stop()
	c := &Client{Addr: addr, Timeout: 2 * time.Second}
	if err := c.SetExitCountry(context.Background(), "SG"); err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 || got[1] != "SETCONF ExitNodes={sg} StrictNodes=1" {
		t.Fatalf("commands = %v", got)
	}
}

func TestSetExitCountryClears(t *testing.T) {
	var got []string
	addr, stop := fakeControl(t, "", &got)
	defer stop()
	c := &Client{Addr: addr, Timeout: 2 * time.Second}
	if err := c.SetExitCountry(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 || got[1] != "SETCONF ExitNodes StrictNodes=0" {
		t.Fatalf("commands = %v", got)
	}
}

// fakeControlReply answers every command with a single fixed reply body.
func fakeControlReply(t *testing.T, reply string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(conn)
			_, _ = br.ReadString('\n') // AUTHENTICATE
			conn.Write([]byte("250 OK\r\n"))
			_, _ = br.ReadString('\n') // GETINFO
			conn.Write([]byte(reply))
			conn.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestBootstrapProgressParsesReply(t *testing.T) {
	addr, stop := fakeControlReply(t,
		"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n")
	defer stop()
	pct, tag, err := (&Client{Addr: addr, Timeout: 2 * time.Second}).BootstrapProgress(context.Background())
	if err != nil {
		t.Fatalf("BootstrapProgress: %v", err)
	}
	if pct != 100 || tag != "done" {
		t.Fatalf("got pct=%d tag=%q", pct, tag)
	}
}

func TestBootstrapProgressPartial(t *testing.T) {
	addr, stop := fakeControlReply(t,
		"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=conn_done SUMMARY=\"x\"\r\n250 OK\r\n")
	defer stop()
	pct, _, err := (&Client{Addr: addr, Timeout: 2 * time.Second}).BootstrapProgress(context.Background())
	if err != nil || pct != 45 {
		t.Fatalf("pct=%d err=%v", pct, err)
	}
}
