package main

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ResponseWriterProxy struct {
	under    http.ResponseWriter
	response HarResponse
	buffer   bytes.Buffer
}

func NewResponseWriterProxy(r http.ResponseWriter) *ResponseWriterProxy {
	return &ResponseWriterProxy{under: r}
}
func (rwp *ResponseWriterProxy) Header() http.Header {
	return rwp.under.Header()
}
func (rwp *ResponseWriterProxy) Write(bs []byte) (int, error) {
	rwp.buffer.Write(bs)
	return rwp.under.Write(bs)
}
func (rwp *ResponseWriterProxy) WriteHeader(statusCode int) {
	rwp.response.Status = statusCode
	rwp.response.Headers = parseStringArrMap(rwp.under.Header())
	rwp.under.WriteHeader(statusCode)
}
func (rwp *ResponseWriterProxy) GetResponse() *HarResponse {
	var bs []byte
	rwp.response.Content = &HarContent{}

	encoding := rwp.under.Header()["Content-Encoding"]
	if encoding != nil && len(encoding)>0 {
		rwp.response.Content.Encoding = encoding[0]
		if encoding[0] == "gzip" {
			gr, _ := gzip.NewReader(&rwp.buffer)
			defer gr.Close()
			bs, _ = ioutil.ReadAll(gr)
		}
	}
	if bs == nil {
		bs = rwp.buffer.Bytes()
	}
	rwp.response.BodySize = int64(len(bs))
	contentType := rwp.under.Header()["Content-Type"]
	if contentType == nil {
		contentType = []string{"text/plain"}
	}
	rwp.response.Content.MimeType = contentType[0]
	rwp.response.Content.Text = string(bs)

	return &rwp.response
}

func fillIPAddress(req *http.Request, harEntry *HarEntry) {
	host, _, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		host = req.URL.Host
	}
	if ip := net.ParseIP(host); ip != nil {
		harEntry.ServerIPAddress = string(ip)
	}

	if ipaddr, err := net.LookupIP(host); err == nil {
		for _, ip := range ipaddr {
			if ip.To4() != nil {
				harEntry.ServerIPAddress = ip.String()
				return
			}
		}
	}
}

var startingEntrySize = 1000

type Har struct {
	HarLog HarLog `json:"log"`
}

type HarCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HarLog struct {
	Version string     `json:"version"`
	Creator HarCreator `json:"creator"`
	Browser string     `json:"browser"`
	Pages   []HarPage  `json:"pages"`
	Entries []HarEntry `json:"entries"`
}

func newHarLog() *HarLog {
	harLog := HarLog{
		Version: "1.2",
		Creator: HarCreator{Name: "TLSProxy", Version: "2.8"},
		Browser: "",
		Pages:   make([]HarPage, 0, 10),
		Entries: makeNewEntries(),
	}
	return &harLog
}

func (harLog *HarLog) addEntry(entry ...HarEntry) {
	entries := harLog.Entries
	m := len(entries)
	n := m + len(entry)
	if n > cap(entries) { // if necessary, reallocate
		// allocate double what's needed, for future growth.
		newEntries := make([]HarEntry, (n+1)*2)
		copy(newEntries, entries)
		entries = newEntries
	}
	entries = entries[0:n]
	copy(entries[m:n], entry)
	harLog.Entries = entries
	log.Println("Added entry to HAR file", entry[0].Request.URL)
}

func makeNewEntries() []HarEntry {
	return make([]HarEntry, 0, startingEntrySize)
}

type HarPage struct {
	ID              string         `json:"id"`
	StartedDateTime time.Time      `json:"startedDateTime"`
	Title           string         `json:"title"`
	PageTimings     HarPageTimings `json:"pageTimings"`
}

type HarEntry struct {
	PageRef         string       `json:"pageRef"`
	StartedDateTime time.Time    `json:"startedDateTime"`
	Time            int64        `json:"time"`
	Request         *HarRequest  `json:"request"`
	Response        *HarResponse `json:"response"`
	Timings         HarTimings   `json:"timings"`
	ServerIPAddress string       `json:"serverIpAddress"`
	Connection      string       `json:"connection"`
}

type HarRequest struct {
	Method      string             `json:"method"`
	URL         string             `json:"url"`
	HTTPVersion string             `json:"httpVersion"`
	Cookies     []HarCookie        `json:"cookies"`
	Headers     []HarNameValuePair `json:"headers"`
	QueryString []HarNameValuePair `json:"queryString"`
	PostData    *HarPostData       `json:"postData"`
	BodySize    int64              `json:"bodySize"`
	HeadersSize int64              `json:"headersSize"`
}

var captureContent = false

func parseRequest(req *http.Request) *HarRequest {
	if req == nil {
		return nil
	}
	harRequest := HarRequest{
		Method:      req.Method,
		URL:         req.URL.String(),
		HTTPVersion: req.Proto,
		Cookies:     parseCookies(req.Cookies()),
		Headers:     parseStringArrMap(req.Header),
		QueryString: parseStringArrMap((req.URL.Query())),
		BodySize:    req.ContentLength,
		HeadersSize: calcHeaderSize(req.Header),
	}

	if captureContent && (req.Method == "POST" || req.Method == "PUT") {
		harRequest.PostData = parsePostData(req)
	}

	return &harRequest
}

func calcHeaderSize(header http.Header) int64 {
	headerSize := 0
	for headerName, headerValues := range header {
		headerSize += len(headerName) + 2
		for _, v := range headerValues {
			headerSize += len(v)
		}
	}
	return int64(headerSize)
}

func parsePostData(req *http.Request) *HarPostData {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Error parsing request to %v: %v\n", req.URL, e)
		}
	}()

	harPostData := new(HarPostData)
	contentType := req.Header["Content-Type"]
	if contentType == nil {
		panic("Missing content type in request")
	}
	harPostData.MimeType = contentType[0]

	if len(req.PostForm) > 0 {
		index := 0
		params := make([]HarPostDataParam, len(req.PostForm))
		for k, v := range req.PostForm {
			param := HarPostDataParam{
				Name:  k,
				Value: strings.Join(v, ","),
			}
			params[index] = param
			index++
		}
		harPostData.Params = params
	} else {
		str, _ := ioutil.ReadAll(req.Body)
		harPostData.Text = string(str)
	}
	return harPostData
}

func parseStringArrMap(stringArrMap map[string][]string) []HarNameValuePair {
	index := 0
	harQueryString := make([]HarNameValuePair, len(stringArrMap))
	for k, v := range stringArrMap {
		escapedKey, _ := url.QueryUnescape(k)
		escapedValues, _ := url.QueryUnescape(strings.Join(v, ","))
		harNameValuePair := HarNameValuePair{
			Name:  escapedKey,
			Value: escapedValues,
		}
		harQueryString[index] = harNameValuePair
		index++
	}
	return harQueryString
}

func parseCookies(cookies []*http.Cookie) []HarCookie {
	harCookies := make([]HarCookie, len(cookies))
	for i, cookie := range cookies {
		harCookie := HarCookie{
			Name:     cookie.Name,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires,
			HTTPOnly: cookie.HttpOnly,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			Value:    cookie.Value,
		}
		harCookies[i] = harCookie
	}
	return harCookies
}

type HarResponse struct {
	Status      int                `json:"status"`
	StatusText  string             `json:"statusText"`
	HTTPVersion string             `json:"httpVersion"`
	Cookies     []HarCookie        `json:"cookies"`
	Headers     []HarNameValuePair `json:"headers"`
	Content     *HarContent        `json:"content"`
	RedirectURL string             `json:"redirectUrl"`
	BodySize    int64              `json:"bodySize"`
	HeadersSize int64              `json:"headersSize"`
}

func proxyResponseWriter(r *http.ResponseWriter) (http.ResponseWriter, *HarResponse) {
	value := &HarResponse{}

	return nil, value
}

func oldParseResponse(resp *http.Response) *HarResponse {
	if resp == nil {
		return nil
	}

	harResponse := HarResponse{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		HTTPVersion: resp.Proto,
		Cookies:     parseCookies(resp.Cookies()),
		Headers:     parseStringArrMap(resp.Header),
		RedirectURL: "",
		BodySize:    resp.ContentLength,
		HeadersSize: calcHeaderSize(resp.Header),
	}

	if captureContent {
		harResponse.Content = parseContent(resp)
	}

	return &harResponse
}

func parseContent(resp *http.Response) *HarContent {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Error parsing response to %v: %v\n", resp.Request.URL, e)
		}
	}()

	harContent := new(HarContent)
	contentType := resp.Header["Content-Type"]
	if contentType == nil {
		panic("Missing content type in response")
	}
	harContent.MimeType = contentType[0]
	if resp.ContentLength <= 0 {
		log.Println("Empty content")
		return nil
	}

	body, _ := ioutil.ReadAll(resp.Body)
	harContent.Text = string(body)
	return harContent
}

type HarCookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path"`
	Domain   string    `json:"domain"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

type HarNameValuePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HarPostData struct {
	MimeType string             `json:"mimeType"`
	Params   []HarPostDataParam `json:"params"`
	Text     string             `json:"text"`
}

type HarPostDataParam struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	FileName    string `json:"fileName"`
	ContentType string `json:"contentType"`
}

type HarContent struct {
	Size        int64  `json:"size"`
	Compression int64  `json:"compression"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text"`
	Encoding    string `json:"encoding"`
}

type HarPageTimings struct {
	OnContentLoad int64 `json:"onContentLoad"`
	OnLoad        int64 `json:"onLoad"`
}

type HarTimings struct {
	Blocked int64 `json:"blocked"`
	DNS     int64 `json:"dns"`
	Connect int64 `json:"connect"`
	Send    int64 `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int64 `json:"receive"`
	Ssl     int64 `json:"ssl"`
}
