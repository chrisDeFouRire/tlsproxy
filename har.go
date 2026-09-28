package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	harDownloadPath = "/downloadharfile"
	// oldest entries are dropped past this many, to bound memory usage
	maxHarEntries = 10000
)

// harRecorder keeps a HAR log of the requests going through the proxy.
// It is safe for concurrent use.
type harRecorder struct {
	mu  sync.Mutex
	log *HarLog
}

func newHarRecorder() *harRecorder {
	return &harRecorder{log: newHarLog()}
}

func (h *harRecorder) addEntry(entry HarEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.log.Entries) >= maxHarEntries {
		h.log.Entries = append(h.log.Entries[:0], h.log.Entries[len(h.log.Entries)-maxHarEntries+1:]...)
	}
	h.log.Entries = append(h.log.Entries, entry)
}

// reset returns the current log and starts a new one.
func (h *harRecorder) reset() *HarLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.log
	h.log = newHarLog()
	return l
}

// handler wraps next, recording every request, and serves the HAR file on
// GET /downloadharfile.
func (h *harRecorder) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == harDownloadPath {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=\"tlsproxy.har\"")
			w.Header().Set("Cache-Control", "no-store")
			if err := json.NewEncoder(w).Encode(Har{HarLog: *h.reset()}); err != nil {
				log.Print("Writing HAR file failed: ", err)
			}
			return
		}

		var (
			ipMu     sync.Mutex
			serverIP string
		)
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if host, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String()); err == nil {
					ipMu.Lock()
					serverIP = host
					ipMu.Unlock()
				}
			},
		}
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))

		start := time.Now()
		harReq := parseRequest(r)
		wp := NewResponseWriterProxy(w)

		next.ServeHTTP(wp, r)

		elapsed := time.Since(start).Milliseconds()
		ipMu.Lock()
		ip := serverIP
		ipMu.Unlock()
		h.addEntry(HarEntry{
			StartedDateTime: start,
			Time:            elapsed,
			Request:         harReq,
			Response:        wp.GetResponse(r.Proto),
			Cache:           HarCache{},
			Timings:         HarTimings{Blocked: -1, DNS: -1, Connect: -1, Ssl: -1, Wait: elapsed},
			ServerIPAddress: ip,
		})
	})
}

// ResponseWriterProxy is a proxy to intercept http.ResponseWriter method calls
type ResponseWriterProxy struct {
	under       http.ResponseWriter
	response    HarResponse
	buffer      bytes.Buffer
	wroteHeader bool
}

// NewResponseWriterProxy creates a new ResponseWriterProxy
func NewResponseWriterProxy(r http.ResponseWriter) *ResponseWriterProxy {
	return &ResponseWriterProxy{under: r}
}

// Header from http.ResponseWriter interface
func (rwp *ResponseWriterProxy) Header() http.Header {
	return rwp.under.Header()
}

// Write from http.ResponseWriter interface
func (rwp *ResponseWriterProxy) Write(bs []byte) (int, error) {
	if !rwp.wroteHeader {
		rwp.WriteHeader(http.StatusOK)
	}
	rwp.buffer.Write(bs)
	return rwp.under.Write(bs)
}

// WriteHeader from http.ResponseWriter interface
func (rwp *ResponseWriterProxy) WriteHeader(statusCode int) {
	if rwp.wroteHeader {
		return
	}
	// informational responses are passed through but not recorded
	if statusCode >= 200 || statusCode == http.StatusSwitchingProtocols {
		rwp.wroteHeader = true
		rwp.response.Status = statusCode
		rwp.response.StatusText = http.StatusText(statusCode)
		rwp.response.Headers = parseValues(rwp.under.Header())
	}
	rwp.under.WriteHeader(statusCode)
}

// Unwrap gives http.ResponseController (used by httputil.ReverseProxy for
// flushing and protocol upgrades) access to the underlying ResponseWriter.
func (rwp *ResponseWriterProxy) Unwrap() http.ResponseWriter {
	return rwp.under
}

// GetResponse returns a HarResponse after the response was written by the handler
func (rwp *ResponseWriterProxy) GetResponse(proto string) *HarResponse {
	header := rwp.under.Header()
	raw := rwp.buffer.Bytes()
	bs := decodeBody(raw, header.Get("Content-Encoding"))

	mimeType := header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	content := &HarContent{
		Size:        int64(len(bs)),
		Compression: int64(len(bs) - len(raw)),
		MimeType:    mimeType,
	}
	if utf8.Valid(bs) {
		content.Text = string(bs)
	} else {
		content.Text = base64.StdEncoding.EncodeToString(bs)
		content.Encoding = "base64"
	}

	rwp.response.HTTPVersion = proto
	rwp.response.Cookies = parseCookies((&http.Response{Header: header}).Cookies())
	if rwp.response.Headers == nil {
		rwp.response.Headers = parseValues(header)
	}
	rwp.response.RedirectURL = header.Get("Location")
	rwp.response.Content = content
	rwp.response.BodySize = int64(len(raw))
	rwp.response.HeadersSize = -1
	return &rwp.response
}

// decodeBody undoes gzip or deflate content encoding, returning bs unchanged
// for any other encoding or if decoding fails.
func decodeBody(bs []byte, encoding string) []byte {
	var r io.Reader
	var err error
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(bs))
	case "deflate":
		// "deflate" is supposed to be zlib wrapped, but some servers send raw deflate
		if r, err = zlib.NewReader(bytes.NewReader(bs)); err != nil {
			r, err = flate.NewReader(bytes.NewReader(bs)), nil
		}
	default:
		return bs
	}
	if err != nil {
		return bs
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		return bs
	}
	return decoded
}

// Har represents the json HAR file format
type Har struct {
	HarLog HarLog `json:"log"`
}

// HarCreator is a field of HAR files
type HarCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HarLog is a field of HAR files
type HarLog struct {
	Version string     `json:"version"`
	Creator HarCreator `json:"creator"`
	Pages   []HarPage  `json:"pages"`
	Entries []HarEntry `json:"entries"`
}

func newHarLog() *HarLog {
	return &HarLog{
		Version: "1.2",
		Creator: HarCreator{Name: "TLSProxy", Version: version},
		Pages:   []HarPage{},
		Entries: make([]HarEntry, 0, 128),
	}
}

// HarPage is a field of HAR files
type HarPage struct {
	ID              string         `json:"id"`
	StartedDateTime time.Time      `json:"startedDateTime"`
	Title           string         `json:"title"`
	PageTimings     HarPageTimings `json:"pageTimings"`
}

// HarEntry is a field of HAR files
type HarEntry struct {
	PageRef         string       `json:"pageref,omitempty"`
	StartedDateTime time.Time    `json:"startedDateTime"`
	Time            int64        `json:"time"`
	Request         *HarRequest  `json:"request"`
	Response        *HarResponse `json:"response"`
	Cache           HarCache     `json:"cache"`
	Timings         HarTimings   `json:"timings"`
	ServerIPAddress string       `json:"serverIPAddress,omitempty"`
	Connection      string       `json:"connection,omitempty"`
}

// HarCache is a field of HAR files
type HarCache struct{}

// HarRequest is a field of HAR files
type HarRequest struct {
	Method      string             `json:"method"`
	URL         string             `json:"url"`
	HTTPVersion string             `json:"httpVersion"`
	Cookies     []HarCookie        `json:"cookies"`
	Headers     []HarNameValuePair `json:"headers"`
	QueryString []HarNameValuePair `json:"queryString"`
	PostData    *HarPostData       `json:"postData,omitempty"`
	BodySize    int64              `json:"bodySize"`
	HeadersSize int64              `json:"headersSize"`
}

func parseRequest(req *http.Request) *HarRequest {
	u := url.URL{Scheme: "https", Host: req.Host, Opaque: req.URL.Opaque, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	harRequest := HarRequest{
		Method:      req.Method,
		URL:         u.String(),
		HTTPVersion: req.Proto,
		Cookies:     parseCookies(req.Cookies()),
		Headers:     parseValues(req.Header),
		QueryString: parseValues(req.URL.Query()),
		BodySize:    req.ContentLength,
		HeadersSize: -1,
	}

	if req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0 {
		harRequest.PostData, harRequest.BodySize = parsePostData(req)
	}

	return &harRequest
}

// parsePostData reads the request body (putting it back in place for the
// proxy) and returns it along with its size on the wire.
func parsePostData(req *http.Request) (*HarPostData, int64) {
	raw, err := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		log.Printf("Error reading request body for %v: %v", req.URL, err)
	}

	mimeType := req.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	body := decodeBody(raw, req.Header.Get("Content-Encoding"))
	postData := &HarPostData{MimeType: mimeType, Params: []HarPostDataParam{}}
	if utf8.Valid(body) {
		postData.Text = string(body)
	} else {
		postData.Text = base64.StdEncoding.EncodeToString(body)
	}
	if strings.HasPrefix(mimeType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(body)); err == nil {
			for k, vs := range values {
				for _, v := range vs {
					postData.Params = append(postData.Params, HarPostDataParam{Name: k, Value: v})
				}
			}
		}
	}
	return postData, int64(len(raw))
}

func parseValues(values map[string][]string) []HarNameValuePair {
	pairs := make([]HarNameValuePair, 0, len(values))
	for k, vs := range values {
		for _, v := range vs {
			pairs = append(pairs, HarNameValuePair{Name: k, Value: v})
		}
	}
	return pairs
}

func parseCookies(cookies []*http.Cookie) []HarCookie {
	harCookies := make([]HarCookie, len(cookies))
	for i, cookie := range cookies {
		harCookie := HarCookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			HTTPOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
		}
		if !cookie.Expires.IsZero() {
			harCookie.Expires = cookie.Expires.UTC().Format(time.RFC3339)
		}
		harCookies[i] = harCookie
	}
	return harCookies
}

// HarResponse is a field of HAR files
type HarResponse struct {
	Status      int                `json:"status"`
	StatusText  string             `json:"statusText"`
	HTTPVersion string             `json:"httpVersion"`
	Cookies     []HarCookie        `json:"cookies"`
	Headers     []HarNameValuePair `json:"headers"`
	Content     *HarContent        `json:"content"`
	RedirectURL string             `json:"redirectURL"`
	BodySize    int64              `json:"bodySize"`
	HeadersSize int64              `json:"headersSize"`
}

// HarCookie is a field of HAR files
type HarCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

// HarNameValuePair is a field of HAR files
type HarNameValuePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HarPostData is a field of HAR files
type HarPostData struct {
	MimeType string             `json:"mimeType"`
	Params   []HarPostDataParam `json:"params"`
	Text     string             `json:"text"`
}

// HarPostDataParam is a field of HAR files
type HarPostDataParam struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

// HarContent is a field of HAR files
type HarContent struct {
	Size        int64  `json:"size"`
	Compression int64  `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text"`
	Encoding    string `json:"encoding,omitempty"`
}

// HarPageTimings is a field of HAR files
type HarPageTimings struct {
	OnContentLoad int64 `json:"onContentLoad"`
	OnLoad        int64 `json:"onLoad"`
}

// HarTimings is a field of HAR files
type HarTimings struct {
	Blocked int64 `json:"blocked"`
	DNS     int64 `json:"dns"`
	Connect int64 `json:"connect"`
	Send    int64 `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int64 `json:"receive"`
	Ssl     int64 `json:"ssl"`
}
