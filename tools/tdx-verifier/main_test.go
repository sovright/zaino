package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/validate"
	"golang.org/x/sys/unix"
)

func TestWriteReceiptCorrelatesExactBytes(t *testing.T) {
	var out bytes.Buffer
	if err := writeReceipt(&out, []byte("quote"), []byte("policy"), []byte{0, 1, 255}); err != nil {
		t.Fatal(err)
	}
	var got verificationReceipt
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.Scope != "quote_signature_current_collateral_and_supplied_field_policy_only" ||
		got.QuoteSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("quote"))) ||
		got.PolicySHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("policy"))) || got.ReportData != "0001ff" {
		t.Fatalf("unexpected receipt: %+v", got)
	}
}

type recordedResponse struct {
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}
type recordingGetter struct {
	inner     *boundedGetter
	responses map[string]recordedResponse
}

func (g *recordingGetter) Get(raw string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), raw)
}
func (g *recordingGetter) GetContext(ctx context.Context, raw string) (map[string][]string, []byte, error) {
	h, b, e := g.inner.GetContext(ctx, raw)
	if e == nil {
		g.responses[raw] = recordedResponse{h, base64.StdEncoding.EncodeToString(b)}
	}
	return h, b, e
}

type fixtureGetter map[string]recordedResponse

func (g fixtureGetter) Get(raw string) (map[string][]string, []byte, error) {
	r, ok := g[raw]
	if !ok {
		return nil, nil, fmt.Errorf("unexpected fixture URL %s", raw)
	}
	b, e := base64.StdEncoding.DecodeString(r.Body)
	return r.Header, b, e
}

func validPolicyJSON() string {
	h := func(n int) string { return strings.Repeat("00", n) }
	return `{"report_data":"` + h(64) + `","minimum_qe_svn":0,"minimum_pce_svn":0,"minimum_tee_tcb_svn":"` + h(16) + `","mr_seam":"` + h(48) + `","mr_signer_seam":"` + h(48) + `","seam_attributes":"` + h(8) + `","td_attributes":"` + h(8) + `","xfam":"` + h(8) + `","mr_td":"` + h(48) + `","mr_config_id":"` + h(48) + `","mr_owner":"` + h(48) + `","mr_owner_config":"` + h(48) + `","rt_mrs":["` + h(48) + `","` + h(48) + `","` + h(48) + `","` + h(48) + `"]}`
}

func TestPolicyValidationPrecedesQuoteIO(t *testing.T) {
	d := t.TempDir()
	policy := filepath.Join(d, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"report_data":"00"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-policy", policy, "-quote", filepath.Join(d, "does-not-exist")})
	if err == nil || strings.Contains(err.Error(), "read quote") {
		t.Fatalf("policy must fail before quote I/O: %v", err)
	}
}

func TestPolicyRejectsDuplicateUnknownAndWidths(t *testing.T) {
	base := validPolicyJSON()
	if _, err := parsePolicy([]byte(strings.Replace(base, `"report_data":`, `"report_data":"`+strings.Repeat("00", 64)+`","report_data":`, 1))); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := parsePolicy([]byte(strings.TrimSuffix(base, "}") + `,"unknown":1}`)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := parsePolicy([]byte(strings.Replace(base, strings.Repeat("00", 64), "00", 1))); err == nil || !strings.Contains(err.Error(), "width") {
		t.Fatalf("width: %v", err)
	}
	if _, err := parsePolicy([]byte(strings.Replace(base, `"report_data"`, `"REPORT_DATA"`, 1))); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("case alias: %v", err)
	}
	debug := "01" + strings.Repeat("00", 7)
	if _, err := parsePolicy([]byte(strings.Replace(base, `"td_attributes":"`+strings.Repeat("00", 8)+`"`, `"td_attributes":"`+debug+`"`, 1))); err == nil || !strings.Contains(err.Error(), "DEBUG") {
		t.Fatalf("debug bit: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGetterBodyAndRequestBounds(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))}, nil
	})}
	g := &boundedGetter{client: client}
	if _, _, err := g.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"); err == nil || !strings.Contains(err.Error(), "body limit") {
		t.Fatalf("body bound: %v", err)
	}
	g.requests = maxRequests
	if _, _, err := g.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"); err == nil || !strings.Contains(err.Error(), "request limit") {
		t.Fatalf("request bound: %v", err)
	}
}

func TestProductionHTTPClientBounds(t *testing.T) {
	g := newGetter()
	if g.client.Timeout != totalNetworkTime {
		t.Fatalf("timeout %v", g.client.Timeout)
	}
	tr, ok := g.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport")
	}
	if tr.Proxy != nil || tr.MaxResponseHeaderBytes != 64<<10 {
		t.Fatal("transport proxy/header policy")
	}
	g.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Location", "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")
		return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, _, err := g.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestReadBoundedRejectsNonRegular(t *testing.T) {
	if _, err := readBounded(t.TempDir(), 16); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestReadBoundedRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readBounded(path, 16); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO open blocked")
	}
}

func TestCanonicalCollateralURLs(t *testing.T) {
	good := []string{"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity", "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000", "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der", "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"}
	for _, raw := range good {
		u, err := url.Parse(raw)
		if err != nil || !allowedCollateralURL(u.Hostname(), u) {
			t.Fatalf("rejected canonical %s", raw)
		}
	}
	bad := []string{"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=%35%30%38%30%36%66%30%30%30%30%30%30", "https://api.trustedservices.intel.com/tdx/certification/v4/qe%2fidentity", "https://certificates.trustedservices.intel.com/other.crl"}
	for _, raw := range bad {
		u, _ := url.Parse(raw)
		if allowedCollateralURL(u.Hostname(), u) {
			t.Fatalf("accepted alias %s", raw)
		}
	}
}

func TestStrictStatusWrapperRejectsEitherGap(t *testing.T) {
	up := pcs.TcbComponentStatusUpToDate
	if err := enforceCurrentStatuses(up, up); err != nil {
		t.Fatal(err)
	}
	if err := enforceCurrentStatuses(pcs.TcbComponentStatusOutOfDate, up); err == nil {
		t.Fatal("accepted stale TDX status")
	}
	if err := enforceCurrentStatuses(up, pcs.TcbComponentStatusOutOfDate); err == nil {
		t.Fatal("accepted stale QE status")
	}
}

func TestSignedQuoteV4FixtureParses(t *testing.T) {
	b, err := os.ReadFile("testdata/signed-quote-v4.dat")
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(b[:2]) != 4 {
		t.Fatal("fixture is not QuoteV4")
	}
	q, err := abi.QuoteToProto(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := q.(*pb.QuoteV4); !ok {
		t.Fatalf("unexpected parsed type %T", q)
	}
}

func TestCurrentSignedDiagnosticFixtureFullPipeline(t *testing.T) {
	b, err := os.ReadFile("testdata/gcp-diagnostic-quote-v4.bin")
	if err != nil {
		t.Fatal(err)
	}
	pbytes, err := os.ReadFile("testdata/gcp-diagnostic-derived-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePolicy(pbytes)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := os.ReadFile("testdata/gcp-diagnostic-collateral.json")
	if err != nil {
		t.Fatal(err)
	}
	var getter fixtureGetter
	if err := json.Unmarshal(cb, &getter); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 12, 16, 0, 0, 0, time.UTC)
	if err := verifyEvidence(context.Background(), b, p, getter, now); err != nil {
		t.Fatalf("positive signed fixture: %v", err)
	}
	if err := verifyEvidence(context.Background(), b, p, getter, time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "expired") {
		t.Fatalf("expired collateral: %v", err)
	}
	parsed, err := abi.QuoteToProto(b)
	if err != nil {
		t.Fatal(err)
	}
	signed := parsed.(*pb.QuoteV4).GetSignedData().GetSignature()
	signed[0] ^= 1
	mut, err := abi.QuoteToAbiBytes(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidence(context.Background(), mut, p, getter, now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("signature mutation: %v", err)
	}
	p.Validate.TdQuoteBodyOptions.ReportData = append([]byte(nil), p.Validate.TdQuoteBodyOptions.ReportData...)
	p.Validate.TdQuoteBodyOptions.ReportData[0] ^= 1
	if err := verifyEvidence(context.Background(), b, p, getter, now); err == nil || !strings.Contains(err.Error(), "supplied field policy") {
		t.Fatalf("report data mutation: %v", err)
	}
}

func TestCaptureCurrentCollateral(t *testing.T) {
	if os.Getenv("ZAINO_CAPTURE_COLLATERAL") != "1" {
		t.Skip("manual authenticated fixture refresh only")
	}
	b, err := os.ReadFile("testdata/gcp-diagnostic-quote-v4.bin")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := os.ReadFile("testdata/gcp-diagnostic-derived-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePolicy(pb)
	if err != nil {
		t.Fatal(err)
	}
	g := &recordingGetter{inner: newGetter(), responses: map[string]recordedResponse{}}
	if err := verifyEvidence(context.Background(), b, p, g, time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(g.responses, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/gcp-diagnostic-collateral.json", out, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSignedFixtureTraversesCryptoAndRefusesStaleTCB(t *testing.T) {
	b, err := os.ReadFile("testdata/signed-quote-v4.dat")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.QuoteToProto(b)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.(*pb.QuoteV4)
	body := q.GetTdQuoteBody()
	p := &closedPolicy{MRSignerSEAM: body.GetMrSignerSeam(), SEAMAttributes: body.GetSeamAttributes(), Validate: validate.Options{
		HeaderOptions:      validate.HeaderOptions{MinimumQeSvn: 0, MinimumPceSvn: 0, QeVendorID: intelQEVendorID},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{MinimumTeeTcbSvn: make([]byte, 16), MrSeam: body.GetMrSeam(), TdAttributes: body.GetTdAttributes(), Xfam: body.GetXfam(), MrTd: body.GetMrTd(), MrConfigID: body.GetMrConfigId(), MrOwner: body.GetMrOwner(), MrOwnerConfig: body.GetMrOwnerConfig(), Rtmrs: body.GetRtmrs(), ReportData: body.GetReportData(), EnableTdDebugCheck: true, EnableTdMigratableCheck: true},
	}}
	err = verifyEvidence(context.Background(), b, p, tdxtesting.TestGetter, time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "TCB status check") {
		t.Fatalf("signed stale fixture refusal: %v", err)
	}
}

func TestGetterRejectsNonAllowlistedBeforeRequest(t *testing.T) {
	g := newGetter()
	for _, u := range []string{"http://api.trustedservices.intel.com/x", "https://example.com/x", "https://api.trustedservices.intel.com:444/x"} {
		if _, _, err := g.Get(u); err == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	if g.requests != 0 {
		t.Fatalf("rejected requests counted: %d", g.requests)
	}
}
