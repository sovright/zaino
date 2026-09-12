package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

const (
	ccelDiagnosticScope = "tdx_quote_ccel_digest_replay_diagnostic_v1"
	maxCCELTableBytes   = 4 << 10
	maxCCELLogBytes     = 1 << 20
	maxCCELEvents       = 4096
	ccelTableMinBytes   = 56
	ccelTableRevision   = 1
	ccelTDXType         = 2
	ccelTDXSubtype      = 0
	tcgEventNoAction    = 3
	tcgAlgSHA384        = 0x000c
	sha384Bytes         = 48
)

type ccelTable struct {
	LogAreaLength uint64
}

func parseCCELTable(data []byte, logBytes int) (ccelTable, error) {
	if len(data) != ccelTableMinBytes {
		return ccelTable{}, errors.New("CCEL table must use the supported 56-byte schema")
	}
	if string(data[:4]) != "CCEL" {
		return ccelTable{}, errors.New("CCEL table signature mismatch")
	}
	if int(binary.LittleEndian.Uint32(data[4:8])) != len(data) {
		return ccelTable{}, errors.New("CCEL table declared length mismatch")
	}
	if data[8] != ccelTableRevision {
		return ccelTable{}, fmt.Errorf("CCEL table revision %d is unsupported", data[8])
	}
	var checksum byte
	for _, b := range data {
		checksum += b
	}
	if checksum != 0 {
		return ccelTable{}, errors.New("CCEL table checksum mismatch")
	}
	if data[36] != ccelTDXType {
		return ccelTable{}, fmt.Errorf("CCEL table type %d is not TDX", data[36])
	}
	if data[37] != ccelTDXSubtype {
		return ccelTable{}, fmt.Errorf("CCEL TDX subtype %d is unsupported", data[37])
	}
	if data[38] != 0 || data[39] != 0 {
		return ccelTable{}, errors.New("CCEL table reserved field is nonzero")
	}
	length := binary.LittleEndian.Uint64(data[40:48])
	if length == 0 || length > maxCCELLogBytes || length != uint64(logBytes) {
		return ccelTable{}, fmt.Errorf("CCEL log length %d does not match supplied bounded log length %d", length, logBytes)
	}
	return ccelTable{LogAreaLength: length}, nil
}

type replayResult struct {
	MeasuredEvents [4]uint32
	Matched        [4]bool
}

type byteCursor struct {
	data []byte
	off  int
}

func (c *byteCursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.data)-c.off {
		return nil, io.ErrUnexpectedEOF
	}
	out := c.data[c.off : c.off+n]
	c.off += n
	return out, nil
}

func (c *byteCursor) u16() (uint16, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (c *byteCursor) u32() (uint32, error) {
	b, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func parseSpecIDEvent(c *byteCursor) error {
	header, err := c.take(32)
	if err != nil {
		return fmt.Errorf("Spec ID event header: %w", err)
	}
	if binary.LittleEndian.Uint32(header[:4]) != 1 {
		return errors.New("Spec ID event must use CC MR index 1")
	}
	if binary.LittleEndian.Uint32(header[4:8]) != tcgEventNoAction {
		return errors.New("first event is not EV_NO_ACTION")
	}
	if !bytes.Equal(header[8:28], make([]byte, 20)) {
		return errors.New("Spec ID legacy digest is nonzero")
	}
	size := binary.LittleEndian.Uint32(header[28:32])
	if size > uint32(len(c.data)-c.off) {
		return errors.New("truncated Spec ID event")
	}
	payload, err := c.take(int(size))
	if err != nil {
		return err
	}
	if len(payload) < 29 || !bytes.Equal(payload[:16], []byte("Spec ID Event03\x00")) {
		return errors.New("invalid crypto-agile Spec ID event")
	}
	if binary.LittleEndian.Uint32(payload[16:20]) != 0 || payload[20] != 0 || payload[21] != 2 || payload[22] != 0 || payload[23] != 2 {
		return errors.New("unsupported Spec ID platform or version framing")
	}
	nAlgs := binary.LittleEndian.Uint32(payload[24:28])
	if nAlgs != 1 || len(payload) < 33 {
		return errors.New("Spec ID must declare exactly SHA-384")
	}
	if binary.LittleEndian.Uint16(payload[28:30]) != tcgAlgSHA384 || binary.LittleEndian.Uint16(payload[30:32]) != sha384Bytes {
		return errors.New("Spec ID algorithm is not SHA-384/48")
	}
	vendorSize := int(payload[32])
	if len(payload) != 33+vendorSize {
		return errors.New("Spec ID vendor data length mismatch")
	}
	return nil
}

func parseAndReplayStrict(log []byte, quotedRTMRs [][]byte) (replayResult, error) {
	if len(quotedRTMRs) != 4 {
		return replayResult{}, errors.New("quote does not contain exactly four RTMRs")
	}
	var current [4][sha384Bytes]byte
	var result replayResult
	c := byteCursor{data: log}
	if err := parseSpecIDEvent(&c); err != nil {
		return replayResult{}, err
	}
	eventCount := 0
	foundPadding := false
	for c.off < len(c.data) {
		if len(c.data)-c.off < 4 {
			return replayResult{}, errors.New("truncated event or padding marker")
		}
		if binary.LittleEndian.Uint32(c.data[c.off:c.off+4]) == ^uint32(0) {
			for _, b := range c.data[c.off:] {
				if b != 0xff {
					return replayResult{}, errors.New("noncanonical bytes after CCEL padding marker")
				}
			}
			foundPadding = true
			break
		}
		eventCount++
		if eventCount > maxCCELEvents {
			return replayResult{}, errors.New("CCEL event count exceeds limit")
		}
		index, err := c.u32()
		if err != nil {
			return replayResult{}, fmt.Errorf("event index: %w", err)
		}
		eventType, err := c.u32()
		if err != nil {
			return replayResult{}, fmt.Errorf("event type: %w", err)
		}
		if index > 4 {
			return replayResult{}, fmt.Errorf("unsupported CC measurement-register index %d", index)
		}
		digestCount, err := c.u32()
		if err != nil {
			return replayResult{}, fmt.Errorf("event digest count: %w", err)
		}
		if digestCount != 1 {
			return replayResult{}, errors.New("event must contain exactly one SHA-384 digest")
		}
		alg, err := c.u16()
		if err != nil {
			return replayResult{}, fmt.Errorf("event digest algorithm: %w", err)
		}
		if alg != tcgAlgSHA384 {
			return replayResult{}, fmt.Errorf("event digest algorithm %#x is not SHA-384", alg)
		}
		digest, err := c.take(sha384Bytes)
		if err != nil {
			return replayResult{}, fmt.Errorf("event digest: %w", err)
		}
		eventSize, err := c.u32()
		if err != nil {
			return replayResult{}, fmt.Errorf("event data size: %w", err)
		}
		if uint64(eventSize) > uint64(len(c.data)-c.off) {
			return replayResult{}, errors.New("event data exceeds remaining log")
		}
		if _, err := c.take(int(eventSize)); err != nil {
			return replayResult{}, err
		}
		if eventType == tcgEventNoAction {
			continue
		}
		if index == 0 {
			return replayResult{}, errors.New("measured CC MR index 0 event cannot be replayed against QuoteV4 RTMRs")
		}
		lane := index - 1
		h := sha512.New384()
		_, _ = h.Write(current[lane][:])
		_, _ = h.Write(digest)
		copy(current[lane][:], h.Sum(nil))
		result.MeasuredEvents[lane]++
	}
	if !foundPadding {
		return replayResult{}, errors.New("CCEL log has no canonical padding terminator")
	}
	for i := range current {
		if len(quotedRTMRs[i]) != sha384Bytes {
			return replayResult{}, fmt.Errorf("quoted RTMR%d width is not 48", i)
		}
		if !bytes.Equal(current[i][:], quotedRTMRs[i]) {
			return replayResult{}, fmt.Errorf("CCEL replay mismatch for RTMR%d", i)
		}
		result.Matched[i] = true
	}
	return result, nil
}

func replayVerifiedQuoteCCEL(quoteBytes, tableBytes, logBytes []byte) (replayResult, error) {
	if _, err := parseCCELTable(tableBytes, len(logBytes)); err != nil {
		return replayResult{}, err
	}
	parsed, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		return replayResult{}, fmt.Errorf("parse verified quote for CCEL: %w", err)
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return replayResult{}, errors.New("verified quote is not QuoteV4")
	}
	return parseAndReplayStrict(logBytes, quote.GetTdQuoteBody().GetRtmrs())
}

type ccelDiagnosticReceipt struct {
	SchemaVersion   uint32    `json:"schema_version"`
	QuoteSHA256     string    `json:"quote_sha256"`
	PolicySHA256    string    `json:"policy_sha256"`
	ReportData      string    `json:"report_data"`
	CCELTableSHA256 string    `json:"ccel_table_sha256"`
	CCELLogSHA256   string    `json:"ccel_log_sha256"`
	MeasuredEvents  [4]uint32 `json:"measured_events"`
	RTMRsMatched    [4]bool   `json:"rt_mrs_matched"`
	Scope           string    `json:"scope"`
}

func writeCCELDiagnosticReceipt(w io.Writer, quote, policy, reportData, table, log []byte, replay replayResult) error {
	receipt := ccelDiagnosticReceipt{
		SchemaVersion:   1,
		QuoteSHA256:     fmt.Sprintf("%x", sha256.Sum256(quote)),
		PolicySHA256:    fmt.Sprintf("%x", sha256.Sum256(policy)),
		ReportData:      hex.EncodeToString(reportData),
		CCELTableSHA256: fmt.Sprintf("%x", sha256.Sum256(table)),
		CCELLogSHA256:   fmt.Sprintf("%x", sha256.Sum256(log)),
		MeasuredEvents:  replay.MeasuredEvents,
		RTMRsMatched:    replay.Matched,
		Scope:           ccelDiagnosticScope,
	}
	return json.NewEncoder(w).Encode(receipt)
}
