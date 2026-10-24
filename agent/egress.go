package agent

import "strings"

// torEgressBlock is the code-owned prompt section that tells an agent it is
// egressing through Tor. Like workerTrafficBlock it is appended after rendering,
// so editing the DB prompt can never drop it.
//
// It is deliberately blunt about what Tor cannot do: a model that keeps trying
// UDP scans or mass directory brute force through a 2.5s-RTT circuit wastes the
// whole run and hammers the exit node.
func torEgressBlock(enabled bool, exitCountry string) string {
	if !enabled {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【出口约束 · Tor】\n")
	b.WriteString("本 Agent 的目标流量经 Tor 出网")
	if c := strings.TrimSpace(exitCountry); c != "" {
		b.WriteString("（出口国家：" + c + "）")
	}
	b.WriteString("。\n")
	b.WriteString("- 延迟约 2–3s/RTT：禁止端口扫描、目录爆破、密码喷洒等量大的动作，只做定向单点验证。\n")
	b.WriteString("- 不支持 UDP：nmap -sU / masscan / naabu -udp 一律不要用。\n")
	b.WriteString("- 所有 DNS 必须经代理解析：curl 用 --socks5-hostname，禁止 dig / nslookup / host。\n")
	b.WriteString("- .onion 目标可直接访问。\n")
	b.WriteString("- 目标返回 403 或挑战页时，可能是出口节点被拉黑：记录该现象并换电路重试一次，不要反复撞同一出口。\n")
	b.WriteString("- 经 Tor 的请求会被平台审计（出口 IP、耗时），不要尝试绕过出口直连。\n")
	return b.String()
}
