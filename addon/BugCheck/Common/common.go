package Common

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
)

var BugScanListPerFile = []PluginBaseFun{}
var BugScanListPerFolder = []PluginBaseFun{}
var BugScanListPerFServer = []PluginBaseFun{}
var BugScanListPerFileJs = []PluginBaseFun{}

var Log4j = log.New(io.Discard, "logger:", log.Lshortfile)

type Request struct {
	Method   string
	URL      url.URL
	CheckUrl url.URL
	Proto    string
	Header   http.Header
	Body     []byte

	raw *http.Request
}

func AddBugScanListPerFile(f PluginBaseFun) {
	BugScanListPerFile = append(BugScanListPerFile, f)
}

func AddBugScanListPerFileJs(f PluginBaseFun) {
	BugScanListPerFileJs = append(BugScanListPerFileJs, f)
}
func AddBugScanListPerFolder(f PluginBaseFun) {
	BugScanListPerFolder = append(BugScanListPerFolder, f)
}
func AddBugScanListPerFServer(f PluginBaseFun) {
	BugScanListPerFServer = append(BugScanListPerFServer, f)
}

func (req *Request) MarshalJSON() ([]byte, error) {
	r := make(map[string]interface{})
	r["method"] = req.Method
	r["url"] = req.URL.String()
	r["proto"] = req.Proto
	r["header"] = req.Header
	return json.Marshal(r)
}

func (req *Request) UnmarshalJSON(data []byte) error {
	r := make(map[string]interface{})
	err := json.Unmarshal(data, &r)
	if err != nil {
		return err
	}

	rawurl, ok := r["url"].(string)
	if !ok {
		return errors.New("url parse error")
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return err
	}

	rawheader, ok := r["header"].(map[string]interface{})
	if !ok {
		return errors.New("rawheader parse error")
	}

	header := make(map[string][]string)
	for k, v := range rawheader {
		vals, ok := v.([]interface{})
		if !ok {
			return errors.New("header parse error")
		}

		svals := make([]string, 0)
		for _, val := range vals {
			sval, ok := val.(string)
			if !ok {
				return errors.New("header parse error")
			}
			svals = append(svals, sval)
		}
		header[k] = svals
	}

	*req = Request{
		Method: r["method"].(string),
		URL:    *u,
		Proto:  r["proto"].(string),
		Header: header,
	}
	return nil
}

func NewRequest(req *http.Request) *Request {
	return &Request{
		Method: req.Method,
		URL:    *req.URL,
		Proto:  req.Proto,
		Header: req.Header,
		raw:    req,
	}
}

func (r *Request) Raw() *http.Request {
	return r.raw
}

type Response struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"-"`

	decodedBody []byte
	decoded     bool // decoded reports whether the response was sent compressed but was decoded to decodedBody.
	decodedErr  error
}

type PocInfo struct {
	Num         int
	Rate        int
	Timeout     int64
	Proxy       string
	PocName     string
	PocDir      string
	Cookie      string
	ForceSSL    bool
	ApiKey      string
	CeyeDomain  string
	GobyPocScan bool
	Target      string
	Request     Request
	Response    Response
	Infostr     []string
}

var Pocinfo = PocInfo{Num: 20, Rate: 20, Timeout: 5}
