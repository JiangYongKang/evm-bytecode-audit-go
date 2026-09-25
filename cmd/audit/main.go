// Command audit runs the local EVM bytecode auditor over the built-in
// sample contracts and prints deterministic JSON reports, one per contract,
// in stable submission order. It needs no network access and no credentials.
//
// Usage:
//
//	go run ./cmd/audit            # audit built-in samples concurrently
//	go run ./cmd/audit -serial    # same analysis, serial execution
//	go run ./cmd/audit -timeout 5s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/highcumontoa/evm-bytecode-audit-go/audit"
	"github.com/highcumontoa/evm-bytecode-audit-go/samples"
)

func main() {
	serial := flag.Bool("serial", false, "analyze contracts one at a time (for comparison with concurrent runs)")
	timeout := flag.Duration("timeout", 2*time.Second, "per-contract timeout (0 disables it)")
	workers := flag.Int("workers", 0, "concurrent workers (0 = auto)")
	flag.Parse()

	analyzer := audit.NewAnalyzer(nil)
	cache := audit.NewCache()
	inputs := samples.Inputs(samples.All())

	var reports []*audit.Report
	if *serial {
		for _, in := range inputs {
			reports = append(reports, analyzer.Analyze(in.Name, in.Code))
		}
	} else {
		reports = audit.NewBatch(analyzer, cache, *timeout, *workers).Run(inputs)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(reports); err != nil {
		fmt.Fprintln(os.Stderr, "encode error:", err)
		os.Exit(1)
	}
}
