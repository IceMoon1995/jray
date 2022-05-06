package Common

import (
	"encoding/json"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"net/http"
	"strings"
)

type Reverse struct {
	ReverseDomain      string
	ReverseCheckDomain string
	//ReversePort        int
	ReverseType        string
	ReverseAccessKeyId string

	DigToken string
	DigKey   string
	Other    string
}

var LdapReverse = Reverse{ReverseDomain: "127.0.0.1:1389", ReverseCheckDomain: "http://127.0.0.1:8080/%s.md5", ReverseType: "ldap"}
var DigReverse = Reverse{ReverseDomain: "", ReverseCheckDomain: "https://dig.pm", ReverseType: "dig"}

var ReverseMap = map[string]Reverse{}

func init() {
	ReverseMap["ldap"] = LdapReverse
	ReverseMap["dig"] = DigReverse
}

func GetDNSLog_Platform_Golang(dnslog_base string) map[string]string {
	header := http.Header{}
	header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")
	urlBase := dnslog_base + "/get_domain"
	result := Ghttp.Analyze(urlBase, "GET", "", header, 4)
	cehckDomain := []string{}
	err := json.Unmarshal([]byte(result.Body), &cehckDomain)
	if err != nil {
		return map[string]string{}
	}
	if result.StatusCode == 200 {
		urlSubDomain := dnslog_base + "/get_sub_domain?domain=" + cehckDomain[0]
		result1 := Ghttp.Analyze(urlSubDomain, "POST", "", header, 4)
		if result1.StatusCode == 200 {
			resultmap := map[string]string{}
			err := json.Unmarshal([]byte(result1.Body), &resultmap)
			if err != nil {
				return nil
			} else {
				return resultmap
			}
		}

	}
	return nil

}

func CheckDNSLog_Platform_Golang(dnslog_base string, mm map[string]string) map[string]string {
	urlSubDomain := dnslog_base + "/get_results"
	domain := mm["domain"]
	domainsp := strings.Split(domain, ".")
	domainsp = domainsp[1:]
	domain = strings.Join(domainsp, ".")
	data := "domain=" + domain + "&" + "token=" + mm["token"]
	//jsondata, _ := json.Marshal(data)
	header := http.Header{}
	header.Set("content-type", "application/x-www-form-urlencoded")
	header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")

	result1 := Ghttp.Analyze(urlSubDomain, "POST", data, header, 4)
	if result1.StatusCode == 200 {
		resultmap := map[string]string{}
		err := json.Unmarshal([]byte(result1.Body), &resultmap)
		if err != nil || resultmap == nil {
			return nil
		} else {
			return resultmap
		}
	}
	return nil
}
