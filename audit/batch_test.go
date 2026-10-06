package audit_test

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/evm-bytecode-audit-go/audit"
	"github.com/highcumontoa/evm-bytecode-audit-go/bytecode"
	"github.com/highcumontoa/evm-bytecode-audit-go/rules"
	"github.com/highcumontoa/evm-bytecode-audit-go/samples"
)

func marshalReports(rs []*audit.Report) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		j, _ := json.Marshal(r)
		out[i] = string(j)
	}
	return out
}

func TestBatch_ConcurrentEqualsSerialAndOrderStable(t *testing.T) {
	inputs := samples.Inputs(samples.All())
	serial := make([]*audit.Report, 0, len(inputs))
	a := audit.NewAnalyzer(nil)
	for _, in := range inputs {
		serial = append(serial, a.Analyze(in.Name, in.Code))
	}

	// Run several concurrent passes (different worker counts, repeated) and
	// compare both content and order with the serial run.
	for _, workers := range []int{1, 2, 4, 16} {
		for iter := 0; iter < 5; iter++ {
			got := audit.NewBatch(audit.NewAnalyzer(nil), audit.NewCache(), 0, workers).Run(inputs)
			if len(got) != len(inputs) {
				t.Fatalf("workers=%d iter=%d: result count %d", workers, iter, len(got))
			}
			gj := marshalReports(got)
			sj := marshalReports(serial)
			for i := range gj {
				if gj[i] != sj[i] {
					t.Fatalf("workers=%d iter=%d index=%d (%s): concurrent != serial",
						workers, iter, i, inputs[i].Name)
				}
				if got[i].Name != inputs[i].Name {
					t.Fatalf("workers=%d: order drifted at index %d", workers, i)
				}
			}
		}
	}
	t.Logf("input=%d mixed contracts x 4 worker counts x 5 runs -> every concurrent report equals serial, order stable", len(inputs))
}

func TestBatch_FailureIsolationAndTimeout(t *testing.T) {
	// Slow rule makes one contract exceed a tiny deadline; the others must
	// still return their normal conclusions.
	slow := &slowRule{delay: 300 * time.Millisecond}
	all := samples.All()
	target := -1
	inputs := make([]audit.ContractInput, len(all))
	for i, s := range all {
		inputs[i] = audit.ContractInput{Name: s.Name, Code: s.Code}
		if s.Name == "benign_empty_stop" {
			target = i
		}
	}
	if target < 0 {
		t.Fatal("target sample not found")
	}
	// Make the slow rule apply only to the target contract, regardless of
	// which worker picks it up: gate on byte length == 1.
	slow.matchLen = 1

	a := audit.NewAnalyzer([]rules.Rule{slow, rules.UncheckedCallRule{}})
	reports := audit.NewBatch(a, nil, 50*time.Millisecond, 4).Run(inputs)

	if reports[target].Status != audit.StatusTimeout {
		t.Fatalf("target status = %s, want timeout (%s)", reports[target].Status, reports[target].RejectDetail)
	}
	t.Logf("input=%s(len=1) -> %s: %s", reports[target].Name, reports[target].Status, reports[target].RejectDetail)

	ok, rejected := 0, 0
	for i, r := range reports {
		if i == target {
			continue
		}
		switch r.Status {
		case audit.StatusOK:
			ok++
		case audit.StatusRejected:
			rejected++
		default:
			t.Fatalf("contract %s contaminated: status=%s", r.Name, r.Status)
		}
	}
	t.Logf("input=remaining %d contracts -> %d ok, %d rejected, none affected by the timeout",
		len(reports)-1, ok, rejected)
	if ok+rejected != len(reports)-1 {
		t.Fatalf("other contracts were affected by the timeout")
	}
}

// slowRule sleeps once per matching contract, exercising the deadline path.
type slowRule struct {
	delay    time.Duration
	matchLen int
	once     sync.Map
}

func (s *slowRule) ID() rules.RuleID { return "SLOW-RULE" }
func (s *slowRule) Version() string  { return "1.0.0" }
func (s *slowRule) Check(c *bytecode.DecodedContract, blocks []bytecode.Block) []rules.Finding {
	if len(c.Code) != s.matchLen {
		return nil
	}
	time.Sleep(s.delay)
	return nil
}

func TestBatch_CacheReturnsConsistentResults(t *testing.T) {
	all := samples.All()
	inputs := samples.Inputs(all)
	cache := audit.NewCache()
	a := audit.NewAnalyzer(nil)

	first := audit.NewBatch(a, cache, 0, 4).Run(inputs)
	second := audit.NewBatch(a, cache, 0, 4).Run(inputs)
	for i := range first {
		j1, _ := json.Marshal(first[i])
		j2, _ := json.Marshal(second[i])
		if string(j1) != string(j2) {
			t.Fatalf("cached pass differs for %s", inputs[i].Name)
		}
	}
	// Distinct inputs have distinct hashes; cache must hold at least the
	// number of distinct byte payloads.
	uniq := map[string]bool{}
	for _, in := range inputs {
		uniq[audit.HashInput(in.Code)] = true
	}
	if cache.Len() != len(uniq) {
		t.Fatalf("cache size = %d, want %d distinct inputs", cache.Len(), len(uniq))
	}
	t.Logf("input=%d contracts, %d distinct hashes -> cached second pass identical, cache size %d",
		len(inputs), len(uniq), cache.Len())
}

func TestCache_NeverReturnsMismatchedInput(t *testing.T) {
	a := audit.NewAnalyzer(nil)
	c := audit.NewCache()
	codeA := []byte{0x00}
	codeB := []byte{0x01} // different bytes -> different hash

	rA := a.Analyze("a", codeA)
	if !c.Put(codeA, rA) {
		t.Fatal("Put for matching input must succeed")
	}
	if got := c.Get(codeB); got != nil {
		t.Fatalf("cache returned report %q for a different input", got.Name)
	}
	// Forging a report with a wrong InputHash must be refused.
	forged := *rA
	forged.InputHash = audit.HashInput(codeB)
	if c.Put(codeA, &forged) {
		t.Fatal("Put must reject a report whose hash does not match the code")
	}
	// Empty/nil inputs do not poison lookups either.
	if got := c.Get(nil); got != nil {
		t.Fatal("nil input must miss cache")
	}
	t.Logf("input=0x00 cached; lookups with 0x01/nil miss; forged hash report refused -> no mismatched conclusions possible")
}

// genLoopedChain builds a contract of n blocks, each with a CALL and a
// JUMPI back edge to itself, falling through to the next block; the final
// block holds the only SSTORE. Every CALL therefore has a long witness
// path and every block carries a loop: a stress shape for path analysis.
func genLoopedChain(n int) []byte {
	var code []byte
	for i := 0; i < n; i++ {
		self := len(code)
		code = append(code, 0x5b)                            // JUMPDEST
		code = append(code, 0x60, 0x00)                      // PUSH1 0
		code = append(code, 0xf1)                            // CALL
		code = append(code, 0x61, byte(self>>8), byte(self)) // PUSH2 self
		code = append(code, 0x57)                            // JUMPI
	}
	code = append(code, 0x5b, 0x55, 0x00) // JUMPDEST SSTORE STOP
	return code
}

func TestBatch_LargeInputScalesAndStaysDeterministic(t *testing.T) {
	const n = 1000
	code := genLoopedChain(n)
	inputs := []audit.ContractInput{{Name: "large_looped_chain", Code: code}}

	start := time.Now()
	serial := audit.NewAnalyzer(nil).Analyze("large_looped_chain", code)
	elapsed := time.Since(start)
	if serial.Status != audit.StatusOK {
		t.Fatalf("status = %s (%s)", serial.Status, serial.RejectDetail)
	}
	if len(serial.Findings) != n {
		t.Fatalf("findings = %d, want %d (one per CALL)", len(serial.Findings), n)
	}
	sj, _ := json.Marshal(serial)
	for _, workers := range []int{1, 4, 8} {
		got := audit.NewBatch(audit.NewAnalyzer(nil), nil, 0, workers).Run(inputs)
		gj, _ := json.Marshal(got[0])
		if string(gj) != string(sj) {
			t.Fatalf("workers=%d: concurrent result differs from serial", workers)
		}
	}
	t.Logf("input=%d blocks x (CALL + loop back-edge), %d bytes -> %d findings in %s; workers 1/4/8 byte-identical",
		n, len(code), len(serial.Findings), elapsed.Round(time.Millisecond))
}
