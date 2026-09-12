package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
	"golang.org/x/sys/unix"
)

const (
	maxPolicyBytes   = 32 << 10
	maxQuoteBytes    = 16 << 10
	maxBodyBytes     = 4 << 20
	maxRequests      = 12
	totalNetworkTime = 30 * time.Second
)

var intelQEVendorID = []byte{0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07}

type policyJSON struct {
	ReportData       string   `json:"report_data"`
	MinimumQESVN     *uint16  `json:"minimum_qe_svn"`
	MinimumPCESVN    *uint16  `json:"minimum_pce_svn"`
	MinimumTEETCBSVN string   `json:"minimum_tee_tcb_svn"`
	MRSEAM           string   `json:"mr_seam"`
	MRSignerSEAM     string   `json:"mr_signer_seam"`
	SEAMAttributes   string   `json:"seam_attributes"`
	TDAttributes     string   `json:"td_attributes"`
	XFAM             string   `json:"xfam"`
	MRTD             string   `json:"mr_td"`
	MRConfigID       string   `json:"mr_config_id"`
	MROwner          string   `json:"mr_owner"`
	MROwnerConfig    string   `json:"mr_owner_config"`
	RTMRs            []string `json:"rt_mrs"`
}

type closedPolicy struct {
	Validate       validate.Options
	MRSignerSEAM   []byte
	SEAMAttributes []byte
}

type boundedGetter struct {
	client   *http.Client
	mu       sync.Mutex
	requests int
}

func (g *boundedGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), rawURL)
}

func (g *boundedGetter) GetContext(ctx context.Context, rawURL string) (map[string][]string, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Port() != "" || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" {
		return nil, nil, fmt.Errorf("collateral URL rejected")
	}
	host := strings.ToLower(u.Hostname())
	if !allowedCollateralURL(host, u) {
		return nil, nil, fmt.Errorf("collateral host rejected: %s", host)
	}
	g.mu.Lock()
	g.requests++
	count := g.requests
	g.mu.Unlock()
	if count > maxRequests {
		return nil, nil, errors.New("collateral request limit exceeded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("collateral HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxBodyBytes {
		return nil, nil, errors.New("collateral body limit exceeded")
	}
	return map[string][]string(resp.Header), body, nil
}

func allowedCollateralURL(host string, u *url.URL) bool {
	if u.RawPath != "" {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Encode() != u.RawQuery {
		return false
	}
	if host == "certificates.trustedservices.intel.com" {
		return u.Path == "/IntelSGXRootCA.der" && u.RawQuery == ""
	}
	if host != "api.trustedservices.intel.com" {
		return false
	}
	switch u.Path {
	case "/tdx/certification/v4/qe/identity":
		return u.RawQuery == ""
	case "/tdx/certification/v4/tcb":
		return len(q) == 1 && len(q["fmspc"]) == 1 && len(q.Get("fmspc")) == 12 && isHex(q.Get("fmspc"))
	case "/sgx/certification/v4/pckcrl":
		ca := q.Get("ca")
		return len(q) == 2 && len(q["ca"]) == 1 && (ca == "platform" || ca == "processor") && len(q["encoding"]) == 1 && q.Get("encoding") == "der"
	default:
		return false
	}
}

func isHex(s string) bool { _, err := hex.DecodeString(s); return err == nil }

func newGetter() *boundedGetter {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: nil, MaxResponseHeaderBytes: 64 << 10}
	return &boundedGetter{client: &http.Client{Transport: transport, Timeout: totalNetworkTime, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func decodeHex(name, value string, width int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("missing %s", name)
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be lowercase or uppercase hexadecimal: %w", name, err)
	}
	if len(b) != width {
		return nil, fmt.Errorf("%s width is %d, want %d", name, len(b), width)
	}
	return b, nil
}

func parsePolicy(data []byte) (*closedPolicy, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	var raw policyJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("policy JSON: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}
	if raw.MinimumQESVN == nil || raw.MinimumPCESVN == nil {
		return nil, errors.New("missing QE/PCE SVN minimum")
	}
	report, err := decodeHex("report_data", raw.ReportData, 64)
	if err != nil {
		return nil, err
	}
	tee, err := decodeHex("minimum_tee_tcb_svn", raw.MinimumTEETCBSVN, 16)
	if err != nil {
		return nil, err
	}
	mrseam, err := decodeHex("mr_seam", raw.MRSEAM, 48)
	if err != nil {
		return nil, err
	}
	signer, err := decodeHex("mr_signer_seam", raw.MRSignerSEAM, 48)
	if err != nil {
		return nil, err
	}
	seamAttrs, err := decodeHex("seam_attributes", raw.SEAMAttributes, 8)
	if err != nil {
		return nil, err
	}
	tdAttrs, err := decodeHex("td_attributes", raw.TDAttributes, 8)
	if err != nil {
		return nil, err
	}
	if attributes := binary.LittleEndian.Uint64(tdAttrs); attributes&1 != 0 || attributes&(uint64(1)<<29) != 0 {
		return nil, errors.New("td_attributes enables DEBUG or MIGRATABLE")
	}
	xfam, err := decodeHex("xfam", raw.XFAM, 8)
	if err != nil {
		return nil, err
	}
	mrtd, err := decodeHex("mr_td", raw.MRTD, 48)
	if err != nil {
		return nil, err
	}
	mrc, err := decodeHex("mr_config_id", raw.MRConfigID, 48)
	if err != nil {
		return nil, err
	}
	mro, err := decodeHex("mr_owner", raw.MROwner, 48)
	if err != nil {
		return nil, err
	}
	mroc, err := decodeHex("mr_owner_config", raw.MROwnerConfig, 48)
	if err != nil {
		return nil, err
	}
	if len(raw.RTMRs) != 4 {
		return nil, fmt.Errorf("rt_mrs count is %d, want 4", len(raw.RTMRs))
	}
	rtmrs := make([][]byte, 4)
	for i := range raw.RTMRs {
		rtmrs[i], err = decodeHex(fmt.Sprintf("rt_mrs[%d]", i), raw.RTMRs[i], 48)
		if err != nil {
			return nil, err
		}
	}
	return &closedPolicy{Validate: validate.Options{
		HeaderOptions:      validate.HeaderOptions{MinimumQeSvn: *raw.MinimumQESVN, MinimumPceSvn: *raw.MinimumPCESVN, QeVendorID: intelQEVendorID},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{MinimumTeeTcbSvn: tee, MrSeam: mrseam, TdAttributes: tdAttrs, Xfam: xfam, MrTd: mrtd, MrConfigID: mrc, MrOwner: mro, MrOwnerConfig: mroc, Rtmrs: rtmrs, ReportData: report, EnableTdDebugCheck: true, EnableTdMigratableCheck: true},
	}, MRSignerSEAM: signer, SEAMAttributes: seamAttrs}, nil
}

func rejectDuplicateKeys(data []byte) error {
	allowed := map[string]bool{"report_data": true, "minimum_qe_svn": true, "minimum_pce_svn": true, "minimum_tee_tcb_svn": true, "mr_seam": true, "mr_signer_seam": true, "seam_attributes": true, "td_attributes": true, "xfam": true, "mr_td": true, "mr_config_id": true, "mr_owner": true, "mr_owner_config": true, "rt_mrs": true}
	dec := json.NewDecoder(bytes.NewReader(data))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("policy JSON must be one object")
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k, ok := kt.(string)
		if !ok {
			return errors.New("object key is not string")
		}
		if !allowed[k] {
			return fmt.Errorf("unknown policy key %q", k)
		}
		if seen[k] {
			return fmt.Errorf("duplicate policy key %q", k)
		}
		seen[k] = true
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	return ensureJSONEOF(dec)
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("policy JSON has trailing value")
		}
		return err
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("could not open bounded file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a nonempty regular file at most %d bytes", path, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || int64(len(b)) > limit {
		return nil, fmt.Errorf("%s changed size or exceeds %d bytes", path, limit)
	}
	return b, nil
}

func verifyEvidence(ctx context.Context, quoteBytes []byte, policy *closedPolicy, getter trust.HTTPSGetter, now time.Time) error {
	if len(quoteBytes) < 2 || binary.LittleEndian.Uint16(quoteBytes[:2]) != 4 {
		return errors.New("only QuoteV4 is accepted")
	}
	parsed, err := abi.QuoteToProto(quoteBytes)
	if err != nil {
		return fmt.Errorf("parse quote: %w", err)
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return errors.New("parsed quote is not QuoteV4")
	}
	if !bytes.Equal(quote.GetTdQuoteBody().GetMrSignerSeam(), policy.MRSignerSEAM) || !bytes.Equal(quote.GetTdQuoteBody().GetSeamAttributes(), policy.SEAMAttributes) {
		return errors.New("SEAM field policy mismatch")
	}
	times := &verify.TimeSet{PckCertChain: now, TcbInfo: now, QeIdentity: now, PckCrl: now, RootCaCrl: now}
	// nil selects the Intel root embedded in the exact pinned verifier module,
	// never ambient operating-system roots.
	options := &verify.Options{CheckRevocations: true, GetCollateral: true, Getter: getter, Now: times, TrustedRoots: nil, DisableTcbStatusCheck: false}
	if err := verify.TdxQuoteContext(ctx, quote, options); err != nil {
		return fmt.Errorf("cryptographic/collateral verification: %w", err)
	}
	tdx, qe, err := verify.SupportedTcbLevelsFromCollateral(quote, options)
	if err != nil {
		return fmt.Errorf("matched TCB levels: %w", err)
	}
	if err := enforceCurrentStatuses(tdx.TcbStatus, qe.TcbStatus); err != nil {
		return err
	}
	if err := validate.TdxQuote(quote, &policy.Validate); err != nil {
		return fmt.Errorf("supplied field policy: %w", err)
	}
	return nil
}

func enforceCurrentStatuses(tdx, qe pcs.TcbComponentStatus) error {
	if tdx != pcs.TcbComponentStatusUpToDate || qe != pcs.TcbComponentStatusUpToDate {
		return fmt.Errorf("strict TCB status refused: tdx=%s qe=%s", tdx, qe)
	}
	return nil
}

type runDependencies struct {
	getter trust.HTTPSGetter
	now    func() time.Time
	stdout io.Writer
}

func run(args []string) error {
	return runWith(args, runDependencies{
		getter: newGetter(),
		now:    time.Now,
		stdout: os.Stdout,
	})
}

func runWith(args []string, dependencies runDependencies) error {
	fs := flag.NewFlagSet("tdx-verifier", flag.ContinueOnError)
	mode := fs.String("mode", "quote", "verification mode: quote or ccel-diagnostic")
	quotePath := fs.String("quote", "", "raw QuoteV4 file")
	policyPath := fs.String("policy", "", "verifier-owned closed policy JSON")
	ccelTablePath := fs.String("ccel-table", "", "CCEL ACPI table file (ccel-diagnostic mode)")
	ccelLogPath := fs.String("ccel-log", "", "raw CCEL event-log area (ccel-diagnostic mode)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *quotePath == "" || *policyPath == "" || fs.NArg() != 0 {
		return errors.New("usage: tdx-verifier [-mode quote|ccel-diagnostic] -quote FILE -policy FILE [-ccel-table FILE -ccel-log FILE]")
	}
	if *mode != "quote" && *mode != "ccel-diagnostic" {
		return fmt.Errorf("unknown verification mode %q", *mode)
	}
	if *mode == "quote" && (*ccelTablePath != "" || *ccelLogPath != "") {
		return errors.New("CCEL inputs require explicit ccel-diagnostic mode")
	}
	if *mode == "ccel-diagnostic" && (*ccelTablePath == "" || *ccelLogPath == "") {
		return errors.New("ccel-diagnostic mode requires both -ccel-table and -ccel-log")
	}
	policyData, err := readBounded(*policyPath, maxPolicyBytes)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	policy, err := parsePolicy(policyData)
	if err != nil {
		return err
	}
	quoteBytes, err := readBounded(*quotePath, maxQuoteBytes)
	if err != nil {
		return fmt.Errorf("read quote: %w", err)
	}
	if len(quoteBytes) < 2 || binary.LittleEndian.Uint16(quoteBytes[:2]) != 4 {
		return errors.New("only QuoteV4 is accepted")
	}
	var ccelTableBytes, ccelLogBytes []byte
	if *mode == "ccel-diagnostic" {
		ccelTableBytes, err = readBounded(*ccelTablePath, maxCCELTableBytes)
		if err != nil {
			return fmt.Errorf("read CCEL table: %w", err)
		}
		ccelLogBytes, err = readBounded(*ccelLogPath, maxCCELLogBytes)
		if err != nil {
			return fmt.Errorf("read CCEL log: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalNetworkTime)
	defer cancel()
	if err := verifyEvidence(ctx, quoteBytes, policy, dependencies.getter, dependencies.now()); err != nil {
		return err
	}
	if *mode == "ccel-diagnostic" {
		replay, err := replayVerifiedQuoteCCEL(quoteBytes, ccelTableBytes, ccelLogBytes)
		if err != nil {
			return fmt.Errorf("strict CCEL digest replay: %w", err)
		}
		if err := writeCCELDiagnosticReceipt(dependencies.stdout, quoteBytes, policyData, policy.Validate.TdQuoteBodyOptions.ReportData, ccelTableBytes, ccelLogBytes, replay); err != nil {
			return fmt.Errorf("write CCEL diagnostic receipt: %w", err)
		}
		return nil
	}
	if err := writeReceipt(dependencies.stdout, quoteBytes, policyData, policy.Validate.TdQuoteBodyOptions.ReportData); err != nil {
		return fmt.Errorf("write receipt: %w", err)
	}
	return nil
}

type verificationReceipt struct {
	SchemaVersion uint32 `json:"schema_version"`
	QuoteSHA256   string `json:"quote_sha256"`
	PolicySHA256  string `json:"policy_sha256"`
	ReportData    string `json:"report_data"`
	Scope         string `json:"scope"`
}

func writeReceipt(w io.Writer, quote, policy, reportData []byte) error {
	receipt := verificationReceipt{
		SchemaVersion: 1,
		QuoteSHA256:   fmt.Sprintf("%x", sha256.Sum256(quote)),
		PolicySHA256:  fmt.Sprintf("%x", sha256.Sum256(policy)),
		ReportData:    hex.EncodeToString(reportData),
		Scope:         "quote_signature_current_collateral_and_supplied_field_policy_only",
	}
	return json.NewEncoder(w).Encode(receipt)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "verification refused:", err)
		os.Exit(1)
	}
}
