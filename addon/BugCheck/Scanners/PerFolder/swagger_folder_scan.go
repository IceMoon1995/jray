package PerFolder

import (
	"jray/addon/BugCheck/Common"
	"strings"
)
import "jray/addon/BugCheck/Ginfo/Ghttp"

func init() {
	Common.AddBugScanListPerFolder(SwagerFolderScan{Common.PluginBase{Name: "SwagerFolderScan", Desc: "Swager接口信息泄露", Type: "FolderScan", Level: 1}})
}

type SwagerFolderScan struct {
	Common.PluginBase
}

func (p SwagerFolderScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()

}
func (p SwagerFolderScan) Audit() {
	file_dic := []string{"swagger-ui.html", "swagger/swagger-ui.html", "api/swagger-ui.html", "service/swagger-ui.html", "web/swagger-ui.html", "actuator/swagger-ui.html", "libs/swagger-ui.html", "template/swagger-ui.html", "admin/swagger-ui.html"}
	url := p.Request.CheckUrl.Scheme + "://" + p.Request.CheckUrl.Host + p.Request.CheckUrl.EscapedPath()
	for _, dic := range file_dic {
		url1 := url + dic
		result := Ghttp.Analyze(url1, "GET", "", nil, 5)
		if result.StatusCode == 200 && (strings.Contains(result.Body, "Swagger") || strings.Contains(result.Body, "swagger")) && (strings.Contains(result.Body, "<html>") || strings.Contains(result.Body, "swagger-ui.min.js")) {
			p.Success(p.Name, url1, p.Type, p.Desc, "")
			return
		}
	}

}
