package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func syntheticSpecID() []byte {
	payload := make([]byte, 33)
	copy(payload[:16], []byte("Spec ID Event03\x00"))
	payload[21] = 2
	payload[23] = 2
	binary.LittleEndian.PutUint32(payload[24:28], 1)
	binary.LittleEndian.PutUint16(payload[28:30], tcgAlgSHA384)
	binary.LittleEndian.PutUint16(payload[30:32], sha384Bytes)
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[:4], 1)
	binary.LittleEndian.PutUint32(header[4:8], tcgEventNoAction)
	binary.LittleEndian.PutUint32(header[28:32], uint32(len(payload)))
	return append(header, payload...)
}

func syntheticEvent(index, eventType uint32, digest byte) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, index)
	_ = binary.Write(&out, binary.LittleEndian, eventType)
	_ = binary.Write(&out, binary.LittleEndian, uint32(1))
	_ = binary.Write(&out, binary.LittleEndian, uint16(tcgAlgSHA384))
	out.Write(bytes.Repeat([]byte{digest}, sha384Bytes))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	return out.Bytes()
}

func syntheticLog(events ...[]byte) []byte {
	out := syntheticSpecID()
	for _, event := range events {
		out = append(out, event...)
	}
	return append(out, bytes.Repeat([]byte{0xff}, 16)...)
}

func zeroRTMRs() [][]byte {
	out := make([][]byte, 4)
	for i := range out {
		out[i] = make([]byte, sha384Bytes)
	}
	return out
}

func expectedSingleExtension(digest byte) []byte {
	h := sha512.New384()
	h.Write(make([]byte, sha384Bytes))
	h.Write(bytes.Repeat([]byte{digest}, sha384Bytes))
	return h.Sum(nil)
}

func syntheticTable(logLength int) []byte {
	table := make([]byte, ccelTableMinBytes)
	copy(table[:4], "CCEL")
	binary.LittleEndian.PutUint32(table[4:8], uint32(len(table)))
	table[8] = 1
	table[36] = ccelTDXType
	binary.LittleEndian.PutUint64(table[40:48], uint64(logLength))
	binary.LittleEndian.PutUint64(table[48:56], 0x1000)
	var sum byte
	for _, b := range table {
		sum += b
	}
	table[9] -= sum
	return table
}

func TestStrictReplayMatchesAllFourLanes(t *testing.T) {
	log := syntheticLog(syntheticEvent(1, 1, 7))
	rtmrs := zeroRTMRs()
	rtmrs[0] = expectedSingleExtension(7)
	got, err := parseAndReplayStrict(log, rtmrs)
	if err != nil {
		t.Fatal(err)
	}
	if got.MeasuredEvents != [4]uint32{1, 0, 0, 0} || got.Matched != [4]bool{true, true, true, true} {
		t.Fatalf("unexpected replay: %+v", got)
	}
}

func TestStrictReplayRejectsDigestAndEmptyRTMR3Mutations(t *testing.T) {
	log := syntheticLog(syntheticEvent(1, 1, 7))
	rtmrs := zeroRTMRs()
	rtmrs[0] = expectedSingleExtension(7)
	mutatedLog := append([]byte(nil), log...)
	mutatedLog[len(syntheticSpecID())+14] ^= 1
	if _, err := parseAndReplayStrict(mutatedLog, rtmrs); err == nil || !strings.Contains(err.Error(), "RTMR0") {
		t.Fatalf("digest mutation accepted: %v", err)
	}
	rtmrs[3][0] = 1
	if _, err := parseAndReplayStrict(log, rtmrs); err == nil || !strings.Contains(err.Error(), "RTMR3") {
		t.Fatalf("empty RTMR3 mutation accepted: %v", err)
	}
}

func TestStrictReplayRejectsNoncanonicalPaddingAndIndex(t *testing.T) {
	rtmrs := zeroRTMRs()
	log := syntheticLog()
	log[len(log)-1] = 0
	if _, err := parseAndReplayStrict(log, rtmrs); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("padding mutation accepted: %v", err)
	}
	if _, err := parseAndReplayStrict(syntheticLog(syntheticEvent(5, 1, 7)), rtmrs); err == nil || !strings.Contains(err.Error(), "index") {
		t.Fatalf("invalid index accepted: %v", err)
	}
	if _, err := parseAndReplayStrict(syntheticLog(syntheticEvent(0, 1, 7)), rtmrs); err == nil || !strings.Contains(err.Error(), "index 0") {
		t.Fatalf("measured MRTD-lane event accepted without MRTD replay: %v", err)
	}
	if _, err := parseAndReplayStrict(syntheticLog(syntheticEvent(0, tcgEventNoAction, 0)), rtmrs); err != nil {
		t.Fatalf("unmeasured CC MR0 annotation rejected: %v", err)
	}
}

func TestStrictReplayRejectsSpecVersionAndRecordFraming(t *testing.T) {
	rtmrs := zeroRTMRs()
	badVersion := syntheticLog()
	badVersion[32+21] = 3
	if _, err := parseAndReplayStrict(badVersion, rtmrs); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("Spec ID version accepted: %v", err)
	}
	badIndex := syntheticLog()
	badIndex[0] = 2
	if _, err := parseAndReplayStrict(badIndex, rtmrs); err == nil || !strings.Contains(err.Error(), "index 1") {
		t.Fatalf("Spec ID index accepted: %v", err)
	}
	eventOffset := len(syntheticSpecID())
	badCount := syntheticLog(syntheticEvent(1, 1, 7))
	badCount[eventOffset+8] = 2
	if _, err := parseAndReplayStrict(badCount, rtmrs); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("digest count accepted: %v", err)
	}
	badAlgorithm := syntheticLog(syntheticEvent(1, 1, 7))
	badAlgorithm[eventOffset+12] = 0x0b
	if _, err := parseAndReplayStrict(badAlgorithm, rtmrs); err == nil || !strings.Contains(err.Error(), "SHA-384") {
		t.Fatalf("digest algorithm accepted: %v", err)
	}
	truncated := syntheticLog(syntheticEvent(1, 1, 7))[:eventOffset+20]
	if _, err := parseAndReplayStrict(truncated, rtmrs); err == nil {
		t.Fatal("truncated digest accepted")
	}
	badDataLength := syntheticLog(syntheticEvent(1, 1, 7))
	binary.LittleEndian.PutUint32(badDataLength[eventOffset+62:eventOffset+66], 1000)
	if _, err := parseAndReplayStrict(badDataLength, rtmrs); err == nil || !strings.Contains(err.Error(), "data exceeds") {
		t.Fatalf("truncated event data accepted: %v", err)
	}
}

func TestStrictReplayRejectsMissingPrematurePaddingAndReorder(t *testing.T) {
	rtmrs := zeroRTMRs()
	withoutPadding := syntheticSpecID()
	if _, err := parseAndReplayStrict(withoutPadding, rtmrs); err == nil || !strings.Contains(err.Error(), "padding") {
		t.Fatalf("missing padding accepted: %v", err)
	}
	premature := append(syntheticSpecID(), bytes.Repeat([]byte{0xff}, 4)...)
	premature = append(premature, syntheticEvent(1, 1, 7)...)
	if _, err := parseAndReplayStrict(premature, rtmrs); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("event after padding accepted: %v", err)
	}
	h := sha512.New384()
	h.Write(make([]byte, sha384Bytes))
	h.Write(bytes.Repeat([]byte{1}, sha384Bytes))
	first := h.Sum(nil)
	h.Reset()
	h.Write(first)
	h.Write(bytes.Repeat([]byte{2}, sha384Bytes))
	rtmrs[0] = h.Sum(nil)
	reordered := syntheticLog(syntheticEvent(1, 1, 2), syntheticEvent(1, 1, 1))
	if _, err := parseAndReplayStrict(reordered, rtmrs); err == nil || !strings.Contains(err.Error(), "RTMR0") {
		t.Fatalf("same-lane reorder accepted: %v", err)
	}
}

func TestStrictReplayEnforcesEventCount(t *testing.T) {
	events := make([][]byte, maxCCELEvents+1)
	for i := range events {
		events[i] = syntheticEvent(1, tcgEventNoAction, 0)
	}
	if _, err := parseAndReplayStrict(syntheticLog(events...), zeroRTMRs()); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("event-count overflow accepted: %v", err)
	}
}

func TestCCELTableRequiresTDXLabelChecksumAndExactLogLength(t *testing.T) {
	log := syntheticLog()
	table := syntheticTable(len(log))
	got, err := parseCCELTable(table, len(log))
	if err != nil || got.LogAreaLength != uint64(len(log)) {
		t.Fatalf("valid table: %+v %v", got, err)
	}
	badType := append([]byte(nil), table...)
	badType[36] = 1
	badType[9]++
	if _, err := parseCCELTable(badType, len(log)); err == nil || !strings.Contains(err.Error(), "not TDX") {
		t.Fatalf("wrong CC label accepted: %v", err)
	}
	badChecksum := append([]byte(nil), table...)
	badChecksum[10]++
	if _, err := parseCCELTable(badChecksum, len(log)); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("bad checksum accepted: %v", err)
	}
	if _, err := parseCCELTable(table, len(log)+1); err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("wrong log length accepted: %v", err)
	}
	badRevision := append([]byte(nil), table...)
	badRevision[8] = 2
	badRevision[9]--
	if _, err := parseCCELTable(badRevision, len(log)); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("unsupported revision accepted: %v", err)
	}
	badSubtype := append([]byte(nil), table...)
	badSubtype[37] = 1
	badSubtype[9]--
	if _, err := parseCCELTable(badSubtype, len(log)); err == nil || !strings.Contains(err.Error(), "subtype") {
		t.Fatalf("unsupported subtype accepted: %v", err)
	}
	extended := append(append([]byte(nil), table...), 0)
	binary.LittleEndian.PutUint32(extended[4:8], uint32(len(extended)))
	if _, err := parseCCELTable(extended, len(log)); err == nil || !strings.Contains(err.Error(), "56-byte") {
		t.Fatalf("extended table accepted: %v", err)
	}
}

func TestCCELDiagnosticReceiptHasDistinctCorrelatedScope(t *testing.T) {
	var out bytes.Buffer
	replay := replayResult{MeasuredEvents: [4]uint32{1, 2, 3, 4}, Matched: [4]bool{true, true, true, true}}
	if err := writeCCELDiagnosticReceipt(&out, []byte("quote"), []byte("policy"), []byte{0, 1}, []byte("table"), []byte("log"), replay); err != nil {
		t.Fatal(err)
	}
	var got ccelDiagnosticReceipt
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Scope != ccelDiagnosticScope || got.Scope == "quote_signature_current_collateral_and_supplied_field_policy_only" ||
		got.QuoteSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("quote"))) ||
		got.PolicySHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("policy"))) ||
		got.CCELTableSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("table"))) ||
		got.CCELLogSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("log"))) ||
		got.ReportData != "0001" || got.RTMRsMatched != replay.Matched {
		t.Fatalf("unexpected diagnostic receipt: %+v", got)
	}
}

func TestCCELModeRequiresBothInputsAndExplicitMode(t *testing.T) {
	if err := run([]string{"-mode", "ccel-diagnostic", "-quote", "q", "-policy", "p"}); err == nil || !strings.Contains(err.Error(), "requires both") {
		t.Fatalf("missing CCEL inputs accepted: %v", err)
	}
	if err := run([]string{"-quote", "q", "-policy", "p", "-ccel-table", "t", "-ccel-log", "l"}); err == nil || !strings.Contains(err.Error(), "explicit") {
		t.Fatalf("implicit CCEL mode accepted: %v", err)
	}
}
