package Ghttp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func Analyze(URL string, method string, postBody string, headers http.Header, timeOut float32) Result {

	var client http.Client
	tr := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = http.Client{
		Timeout:       time.Second * time.Duration(timeOut), //timeout
		Transport:     &tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequest(method, URL, strings.NewReader(postBody))
	if err != nil {
		return Result{URL: URL, err: err}
	}
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36")
	if headers != nil {
		for k, _ := range headers {
			req.Header.Set(k, headers.Get(k))
		}
	}
	resp, err := client.Do(req)

	if err != nil {
		return Result{URL: URL, err: err}
	}

	var fullURL string

	builder := &strings.Builder{}
	builder.WriteString(fullURL)

	defer resp.Body.Close()
	var titles []string
	body, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		title1 := ExtractTitle(string(body), resp)
		titles = append(titles, title1)
	}
	title := strings.Join(titles, "|")

	serverHeader1 := resp.Header.Get("Server")
	serverHeader2 := resp.Header.Get("X-Powered-By")
	var serverHeaders []string
	if serverHeader1 != "" {
		serverHeaders = append(serverHeaders, serverHeader1)
	}
	if serverHeader2 != "" {
		serverHeaders = append(serverHeaders, serverHeader2)
	}
	serverHeader := strings.Join(serverHeaders, "|")

	//// web socket
	//isWebSocket := resp.StatusCode == 101

	return Result{
		URL:           fullURL,
		ContentLength: len(body),
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		ContentType:   resp.Header.Get("Content-Type"),
		Title:         title,
		WebServer:     serverHeader,
		str:           builder.String(),
		Body:          string(body),
	}
}

// Result of a scan
type Result struct {
	URL           string      `json:"url"`
	Title         string      `json:"title"`
	Headers       http.Header `json:"headers"`
	WebServer     string      `json:"webserver"`
	ContentType   string      `json:"content-type,omitempty"`
	ContentLength int         `json:"content-length"`
	StatusCode    int         `json:"status-code"`
	err           error
	str           string
	Body          string
}

// JSON the result
func (r *Result) JSON() string {
	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}

func hostsFrom(ss []string) []string {
	for i, s := range ss {
		u, _ := url.Parse(s)
		if host := u.Hostname(); host != "" {
			ss[i] = host
		}
	}
	return ss
}

type hostinfo struct {
	Host  string
	Port  int
	Certs []*x509.Certificate
}

func (h *hostinfo) getCerts(timeout time.Duration) error {
	//log.Printf("connecting to %s:%d", h.Host, h.Port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		h.Host+":"+strconv.Itoa(h.Port),
		&tls.Config{
			InsecureSkipVerify: true,
		})
	if err != nil {
		return err
	}

	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return err
	}

	pc := conn.ConnectionState().PeerCertificates
	h.Certs = make([]*x509.Certificate, 0, len(pc))
	for _, cert := range pc {
		if cert.IsCA {
			continue
		}
		h.Certs = append(h.Certs, cert)
	}

	return nil
}

func CertInfo(host string, port string, timeout time.Duration) (commonName string, dnsNames []string, err error) {
	port_int, err := strconv.Atoi(port)
	if err != nil {
		return commonName, dnsNames, err
	}
	info := hostinfo{Host: host, Port: port_int}
	err = info.getCerts(timeout)
	if err != nil {
		return commonName, dnsNames, err
	}
	for _, cert := range info.Certs {
		if cert != nil && cert.Subject.CommonName != "" {
			return cert.Subject.CommonName, cert.DNSNames, err
		}
	}
	return commonName, dnsNames, errors.New("not found")
}

func GetCert(domain string, port int) (string, error) {
	var CN string
	var DN []string
	var ret string
	var err error
	if port > 0 {
		CN, DN, err = CertInfo(domain, strconv.Itoa(port), 5*time.Second)
	} else {
		CN, DN, err = CertInfo(domain, "443", 5*time.Second)
	}
	ret = "CommonName:" + CN + "; "
	if len(DN) > 0 {
		ret = ret + "DNSName:"
		ret = ret + DN[0]
	}
	return ret, err
}
