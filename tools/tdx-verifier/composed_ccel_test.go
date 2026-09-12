package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

func writeFixtureFile(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadComposedFixture(t *testing.T) ([]byte, []byte, fixtureGetter, []byte) {
	t.Helper()
	quote, err := os.ReadFile("testdata/gcp-diagnostic-quote-v4.bin")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile("testdata/gcp-diagnostic-derived-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	collateral, err := os.ReadFile("testdata/gcp-diagnostic-collateral.json")
	if err != nil {
		t.Fatal(err)
	}
	var getter fixtureGetter
	if err := json.Unmarshal(collateral, &getter); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile("testdata/gcp-diagnostic-digest-only-ccel.bin")
	if err != nil {
		t.Fatal(err)
	}
	return quote, policy, getter, log
}

func runComposedFixture(t *testing.T, now time.Time, quote, policy, table, log []byte, getter fixtureGetter) ([]byte, error) {
	t.Helper()
	directory := t.TempDir()
	args := []string{
		"-mode", "ccel-diagnostic",
		"-quote", writeFixtureFile(t, directory, "quote.bin", quote),
		"-policy", writeFixtureFile(t, directory, "policy.json", policy),
		"-ccel-table", writeFixtureFile(t, directory, "ccel-table.bin", table),
		"-ccel-log", writeFixtureFile(t, directory, "ccel-log.bin", log),
	}
	var output bytes.Buffer
	err := runWith(args, runDependencies{getter: getter, now: func() time.Time { return now }, stdout: &output})
	return output.Bytes(), err
}

func mutateFirstMeasuredDigest(t *testing.T, log []byte) []byte {
	t.Helper()
	mutated := append([]byte(nil), log...)
	cursor := byteCursor{data: mutated}
	if err := parseSpecIDEvent(&cursor); err != nil {
		t.Fatal(err)
	}
	for cursor.off < len(cursor.data) {
		index, err := cursor.u32()
		if err != nil {
			t.Fatal(err)
		}
		eventType, err := cursor.u32()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cursor.take(6); err != nil {
			t.Fatal(err)
		}
		digestOffset := cursor.off
		if _, err := cursor.take(sha384Bytes); err != nil {
			t.Fatal(err)
		}
		eventSize, err := cursor.u32()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cursor.take(int(eventSize)); err != nil {
			t.Fatal(err)
		}
		if eventType != tcgEventNoAction && index == 1 {
			mutated[digestOffset] ^= 1
			return mutated
		}
	}
	t.Fatal("fixture has no measured RTMR0 event")
	return nil
}

func TestSignedQuoteAndDigestOnlyCCELTraverseComposedCLIPath(t *testing.T) {
	quote, policy, getter, log := loadComposedFixture(t)
	table := syntheticTable(len(log))
	now := time.Date(2026, time.September, 12, 16, 0, 0, 0, time.UTC)

	output, err := runComposedFixture(t, now, quote, policy, table, log, getter)
	if err != nil {
		t.Fatalf("composed diagnostic fixture: %v", err)
	}
	var receipt ccelDiagnosticReceipt
	if err := json.Unmarshal(output, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Scope != ccelDiagnosticScope ||
		receipt.QuoteSHA256 != fmt.Sprintf("%x", sha256.Sum256(quote)) ||
		receipt.PolicySHA256 != fmt.Sprintf("%x", sha256.Sum256(policy)) ||
		receipt.CCELTableSHA256 != fmt.Sprintf("%x", sha256.Sum256(table)) ||
		receipt.CCELLogSHA256 != fmt.Sprintf("%x", sha256.Sum256(log)) ||
		receipt.MeasuredEvents != [4]uint32{18, 8, 86, 0} ||
		receipt.RTMRsMatched != [4]bool{true, true, true, true} {
		t.Fatalf("unexpected composed receipt: %+v", receipt)
	}

	parsed, err := abi.QuoteToProto(quote)
	if err != nil {
		t.Fatal(err)
	}
	signature := parsed.(*pb.QuoteV4).GetSignedData().GetSignature()
	signature[0] ^= 1
	badSignature, err := abi.QuoteToAbiBytes(parsed)
	if err != nil {
		t.Fatal(err)
	}

	var policyObject map[string]any
	if err := json.Unmarshal(policy, &policyObject); err != nil {
		t.Fatal(err)
	}
	reportData := policyObject["report_data"].(string)
	policyObject["report_data"] = "01" + reportData[2:]
	badPolicy, err := json.Marshal(policyObject)
	if err != nil {
		t.Fatal(err)
	}

	badTable := append([]byte(nil), table...)
	badTable[10] ^= 1
	badLog := mutateFirstMeasuredDigest(t, log)

	cases := []struct {
		name       string
		now        time.Time
		quote      []byte
		policy     []byte
		table      []byte
		log        []byte
		wantReason string
	}{
		{"signature", now, badSignature, policy, table, log, "signature"},
		{"policy", now, quote, badPolicy, table, log, "supplied field policy"},
		{"table", now, quote, policy, badTable, log, "checksum"},
		{"log", now, quote, policy, table, badLog, "RTMR0"},
		{"stale collateral", time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC), quote, policy, table, log, "expired"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			output, err := runComposedFixture(t, test.now, test.quote, test.policy, test.table, test.log, getter)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantReason)) {
				t.Fatalf("wanted refusal containing %q, got %v", test.wantReason, err)
			}
			if len(output) != 0 {
				t.Fatalf("refused composed verification emitted receipt bytes: %q", output)
			}
		})
	}
}
