package main

import (
	"bufio"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSListener returns a TLS listener configured like the real proxy,
// but with a self-signed certificate instead of Let's Encrypt.
func startTLSListener(t *testing.T, minVersion uint16, nextProtos []string) net.Listener {
	t.Helper()
	cert := selfSignedCert(t)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return tls.NewListener(ln, newTLSConfig(getCert, minVersion, nextProtos))
}

func TestTLSVersionsAndPostQuantum(t *testing.T) {
	tests := []struct {
		name       string
		minVersion uint16
		client     *tls.Config
		wantErr    bool
		wantVer    uint16
		wantCurve  tls.CurveID
	}{
		{"default client gets TLS 1.3 with X25519MLKEM768", tls.VersionTLS12, &tls.Config{}, false, tls.VersionTLS13, tls.X25519MLKEM768},
		{"SecP256r1MLKEM768", tls.VersionTLS12, &tls.Config{CurvePreferences: []tls.CurveID{tls.SecP256r1MLKEM768}}, false, tls.VersionTLS13, tls.SecP256r1MLKEM768},
		{"SecP384r1MLKEM1024", tls.VersionTLS12, &tls.Config{CurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024}}, false, tls.VersionTLS13, tls.SecP384r1MLKEM1024},
		{"classical X25519 still works", tls.VersionTLS12, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}}, false, tls.VersionTLS13, tls.X25519},
		{"TLS 1.2 client allowed by default", tls.VersionTLS12, &tls.Config{MaxVersion: tls.VersionTLS12}, false, tls.VersionTLS12, tls.X25519},
		{"TLS 1.2 client refused with -mintls=1.3", tls.VersionTLS13, &tls.Config{MaxVersion: tls.VersionTLS12}, true, 0, 0},
		{"TLS 1.1 client refused", tls.VersionTLS12, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}, true, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln := startTLSListener(t, tt.minVersion, []string{"http/1.1"})
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.(*tls.Conn).Handshake()
				c.Close()
			}()

			cfg := tt.client.Clone()
			cfg.InsecureSkipVerify = true
			conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
			if tt.wantErr {
				if err == nil {
					conn.Close()
					t.Fatal("handshake succeeded, want failure")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			st := conn.ConnectionState()
			if st.Version != tt.wantVer {
				t.Errorf("version = %s, want %s", tls.VersionName(st.Version), tls.VersionName(tt.wantVer))
			}
			if st.CurveID != tt.wantCurve {
				t.Errorf("key exchange = %s, want %s", st.CurveID, tt.wantCurve)
			}
		})
	}
}

func TestHTTPProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s query=%s proto=%s xff=%s",
			r.Host, r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-For"))
	}))
	defer backend.Close()

	target, err := parseBackendURL(backend.URL + "/base/")
	if err != nil {
		t.Fatal(err)
	}
	ln := startTLSListener(t, tls.VersionTLS12, []string{"h2", "http/1.1"})
	srv := &http.Server{Handler: newReverseProxy(target)}
	go srv.Serve(ln)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/some/page/?a=1", nil)
	req.Host = "www.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.ProtoMajor != 2 {
		t.Errorf("proto = %s, want HTTP/2", resp.Proto)
	}
	want := `host=www.example.com path=/base/some/page/ query=a=1 proto=https xff=127.0.0.1`
	if string(body) != want {
		t.Errorf("backend saw\n %s\nwant\n %s", body, want)
	}
}

func TestParseBackendURL(t *testing.T) {
	for _, s := range []string{"", "localhost:80", "ftp://host", "http://", "://bad"} {
		if _, err := parseBackendURL(s); err == nil {
			t.Errorf("parseBackendURL(%q) succeeded, want error", s)
		}
	}
	if _, err := parseBackendURL("http://web:8080/app"); err != nil {
		t.Error(err)
	}
}

func TestCheckHostPort(t *testing.T) {
	for _, s := range []string{"", "localhost", "http://x", "http://web:80", ":80", "web:http", "web:99999"} {
		if checkHostPort(s) == nil {
			t.Errorf("checkHostPort(%q) succeeded, want error", s)
		}
	}
	for _, s := range []string{"localhost:80", "10.0.0.1:8080", "[::1]:80"} {
		if err := checkHostPort(s); err != nil {
			t.Error(err)
		}
	}
}

func TestSplitHostnames(t *testing.T) {
	got := splitHostnames(" a.com, b.com,,c.com ")
	if strings.Join(got, "|") != "a.com|b.com|c.com" {
		t.Errorf("got %q", got)
	}
	if len(splitHostnames("")) != 0 {
		t.Error("empty whitelist should give no hostnames")
	}
}

func TestHAR(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			w.Write(b) // implicit 200, no WriteHeader call
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		w.WriteHeader(http.StatusTeapot)
		gz := gzip.NewWriter(w)
		gz.Write([]byte("hello world"))
		gz.Close()
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	proxy := httptest.NewTLSServer(newHarRecorder().handler(newReverseProxy(target)))
	defer proxy.Close()
	client := proxy.Client()
	client.Transport.(*http.Transport).DisableCompression = true

	resp, err := client.Get(proxy.URL + "/gz?x=y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = client.Post(proxy.URL+"/form", "application/x-www-form-urlencoded", strings.NewReader("k=v"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "k=v" {
		t.Errorf("POST body not forwarded intact: %q", b)
	}
	resp.Body.Close()

	resp, err = client.Get(proxy.URL + harDownloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var har Har
	if err := json.NewDecoder(resp.Body).Decode(&har); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if len(har.HarLog.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(har.HarLog.Entries))
	}
	gz := har.HarLog.Entries[0]
	if gz.Response.Status != http.StatusTeapot || gz.Response.Content.Text != "hello world" || gz.Response.Content.Encoding != "" {
		t.Errorf("gzip entry response = %+v content = %+v", gz.Response, gz.Response.Content)
	}
	if len(gz.Response.Cookies) != 1 || gz.Response.Cookies[0].Name != "session" {
		t.Errorf("response cookies = %+v", gz.Response.Cookies)
	}
	if !strings.HasPrefix(gz.Request.URL, "https://") || !strings.HasSuffix(gz.Request.URL, "/gz?x=y") {
		t.Errorf("request URL = %s, want absolute URL", gz.Request.URL)
	}
	if gz.ServerIPAddress != "127.0.0.1" {
		t.Errorf("server IP = %q", gz.ServerIPAddress)
	}
	post := har.HarLog.Entries[1]
	if post.Response.Status != http.StatusOK {
		t.Errorf("implicit status = %d, want 200", post.Response.Status)
	}
	if post.Request.PostData == nil || post.Request.PostData.Text != "k=v" || len(post.Request.PostData.Params) != 1 {
		t.Errorf("post data = %+v", post.Request.PostData)
	}

	// the log is reset after each download
	resp, _ = client.Get(proxy.URL + harDownloadPath)
	json.NewDecoder(resp.Body).Decode(&har)
	resp.Body.Close()
	if len(har.HarLog.Entries) != 0 {
		t.Errorf("got %d entries after reset, want 0", len(har.HarLog.Entries))
	}
}

func TestHARConcurrent(t *testing.T) {
	rec := newHarRecorder()
	h := rec.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	done := make(chan struct{})
	for range 20 {
		go func() {
			for range 50 {
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			}
			done <- struct{}{}
		}()
	}
	for range 5 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, harDownloadPath, nil))
	}
	for range 20 {
		<-done
	}
}

func TestProxyHeader(t *testing.T) {
	tcp := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	tests := []struct{ src, dst, want string }{
		{"1.2.3.4:5678", "10.0.0.1:443", "PROXY TCP4 1.2.3.4 10.0.0.1 5678 443\r\n"},
		{"[2001:db8::1]:5678", "[2001:db8::2]:443", "PROXY TCP6 2001:db8::1 2001:db8::2 5678 443\r\n"},
		{"[::ffff:1.2.3.4]:5678", "[::ffff:10.0.0.1]:443", "PROXY TCP4 1.2.3.4 10.0.0.1 5678 443\r\n"},
		{"1.2.3.4:5678", "[2001:db8::2]:443", "PROXY UNKNOWN\r\n"},
	}
	for _, tt := range tests {
		if got := proxyHeader(tcp(tt.src), tcp(tt.dst)); got != tt.want {
			t.Errorf("proxyHeader(%s, %s) = %q, want %q", tt.src, tt.dst, got, tt.want)
		}
	}
}

func TestTCPForward(t *testing.T) {
	// backend reads the PROXY header and a request line, then answers with both
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		header, _ := r.ReadString('\n')
		line, _ := r.ReadString('\n')
		io.WriteString(c, header+line)
	}()

	ln := startTLSListener(t, tls.VersionTLS12, []string{"http/1.1"})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		forward(backendLn.Addr().String(), c, true)
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "hello\n")
	conn.CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "PROXY TCP4 127.0.0.1 127.0.0.1 "
	if !strings.HasPrefix(string(got), wantPrefix) || !strings.HasSuffix(string(got), "\r\nhello\n") {
		t.Errorf("backend echoed %q", got)
	}
}
