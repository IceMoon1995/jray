package PerFolder

import (
	"jray/addon/BugCheck/Common"
	"strings"
)
import "jray/addon/BugCheck/Ginfo/Ghttp"

func init() {
	Common.AddBugScanListPerFolder(ActuatorFolderScan{Common.PluginBase{Name: "ActuatorFolderScan", Desc: "Spring boot Actuator信息泄露", Type: "FolderScan", Level: 1}})
}

type ActuatorFolderScan struct {
	Common.PluginBase
}

func (p ActuatorFolderScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()
}
func (p ActuatorFolderScan) Audit() {
	file_dic := []string{"actuator", "env", "actuator/env", "actuator/info", "actuator/health", "actuator/beans", "actuator/jolokia", "actuator/conditions", "actuator/httptrace", "actuator/mappings", "actuator/configprops", "actuator/threaddump"}
	url := p.Request.CheckUrl.Scheme + "://" + p.Request.CheckUrl.Host + p.Request.CheckUrl.EscapedPath()
	for _, dic := range file_dic {
		url1 := url + dic
		result := Ghttp.Analyze(url1, "GET", "", nil, 5)
		if result.StatusCode == 200 && strings.HasPrefix(result.Body, "{") && strings.HasSuffix(result.Body, "}") && !strings.Contains(result.Body, ",\"code\":") {
			p.Success(p.Name, url1, p.Type, p.Desc, "")
			return
		}
	}
	url2 := url + "/actuator/heapdump"
	result := Ghttp.Analyze(url2, "HEAD", "", nil, 5)
	if result.StatusCode == 200 && strings.Contains(result.ContentType, "application/octet-stream") {
		p.Success(p.Name, url2, p.Type, p.Desc, "")
		return
	}
}
