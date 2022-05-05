package Java

import (
	"encoding/json"
	"fmt"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"strings"
)

func init() {
	Common.AddBugScanListPerFile(Spring4ShellScan{Common.PluginBase{Name: "Spring4ShellScan", Desc: "SpringMVC框架在JDK9及以上版本存在rce漏洞（CVE-2022-22965）,此poc只是检测可能存在漏洞的点，是否真实存在漏洞需要手工验证", Type: "RCE", Level: 2, TimeOut: 3, Ltype: "JAVA"}})
}

type Spring4ShellScan struct {
	Common.PluginBase
}

func (p Spring4ShellScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()

}
func (p Spring4ShellScan) Audit() {

	if len(p.Request.Body) > 0 || p.Request.URL.RawQuery != "" {
		r1 := Common.RandStr(8)
		r2 := Common.RandStr(8)
		main_payload := fmt.Sprintf("class.module.classLoader[%s]=%s", r1, r2)

		if p.Request.Method == "GET" && p.Request.URL.RawQuery != "" {
			url2 := p.Request.CheckUrl.String()
			result2 := Ghttp.Analyze(url2, "GET", "", p.Request.Header, p.TimeOut)
			requestVuls := p.Request.CheckUrl.Query()
			for k1, _ := range requestVuls {
				v1 := requestVuls.Get(k1)
				requestVuls.Set(k1, main_payload)
				p.Request.CheckUrl.RawQuery = requestVuls.Encode()
				result := Ghttp.Analyze(p.Request.CheckUrl.String(), "GET", "", p.Request.Header, p.TimeOut)
				if result.StatusCode != 200 && result.StatusCode != 404 && result.StatusCode != result2.StatusCode {
					p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, "")
					return
				}
				requestVuls.Set(k1, v1)
				break
			}

		} else if p.Request.Method != "GET" && len(p.Request.Body) > 0 {

			contentType := p.Request.Header.Get("Content-Type")
			result2 := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(p.Request.Body), p.Request.Header, p.TimeOut)
			if strings.Contains(contentType, "application/x-www-form-urlencoded") || !strings.Contains(contentType, "application/json") {
				p.Request.CheckUrl.RawQuery = string(p.Request.Body)
				requestVuls := p.Request.CheckUrl.Query()

				for k1, _ := range requestVuls {
					v1 := requestVuls.Get(k1)
					requestVuls.Set(k1, main_payload)

					result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, requestVuls.Encode(), p.Request.Header, p.TimeOut)
					if result.StatusCode != 200 && result.StatusCode != 404 && result.StatusCode != result2.StatusCode {
						p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, "")
						return
					}
					requestVuls.Set(k1, v1)
					break
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
						m[k] = main_payload
						bodym, _ := json.Marshal(m)
						result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(bodym), p.Request.Header, p.TimeOut)
						if result.StatusCode != 200 && result.StatusCode != 404 && result.StatusCode != result2.StatusCode {
							p.Success(p.Name, p.Request.CheckUrl.String(), p.Type, p.Desc, "")
							return
						}

					case int:
					case float64:
					case []interface{}:
					default:
					}
				}
			}
		}
	}

}
