// audit 是本地 EVM 字节码审计命令行入口。
//
// 用法：
//
//	audit <hexfile...>     分析包含十六进制字节码的本地文件
//	audit -hex 0x6000ff    直接分析内联十六进制字节码（可多次给出）
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/highcumontoa/evm-bytecode-audit-go/internal/audit"
)

type hexFlags []string

func (h *hexFlags) String() string { return strings.Join(*h, ",") }
func (h *hexFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func main() {
	var hexes hexFlags
	workers := flag.Int("workers", 4, "并发分析的 worker 数")
	flag.Var(&hexes, "hex", "内联十六进制字节码（可重复）")
	flag.Parse()

	var contracts [][]byte
	var labels []string
	for _, h := range hexes {
		code, err := parseHex(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -hex %q: %v\n", h, err)
			os.Exit(2)
		}
		contracts = append(contracts, code)
		labels = append(labels, "hex:"+h)
	}
	for _, path := range flag.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(2)
		}
		code, err := parseHex(string(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
			os.Exit(2)
		}
		contracts = append(contracts, code)
		labels = append(labels, path)
	}
	if len(contracts) == 0 {
		fmt.Fprintln(os.Stderr, "no input: use -hex 0x... or pass hex files")
		os.Exit(2)
	}

	b := audit.NewBatchAuditor(audit.NewAnalyzer(), *workers)
	results := b.Run(context.Background(), contracts)
	exit := 0
	for i, r := range results {
		fmt.Printf("== [%d] %s\n", i, labels[i])
		if r.Err != nil {
			fmt.Printf("   ERROR: %v\n", r.Err)
			exit = 1
			continue
		}
		rep := r.Report
		fmt.Printf("   hash=%s ruleset=%s status=%s\n", rep.CodeHash[:16], rep.RulesetID, rep.Status)
		if rep.Reject != nil {
			fmt.Printf("   reject: %s\n", rep.Reject)
		}
		for _, f := range rep.Findings {
			fmt.Printf("   finding: %s\n", f)
		}
		if rep.Status == audit.StatusFlagged {
			exit = 1
		}
	}
	os.Exit(exit)
}

func parseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var b byte
		if _, err := fmt.Sscanf(s[i:i+2], "%02x", &b); err != nil {
			return nil, fmt.Errorf("bad hex at %d: %w", i, err)
		}
		out = append(out, b)
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %d", len(s))
	}
	return out, nil
}
