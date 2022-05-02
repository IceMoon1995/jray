package PerFolder

import (
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"regexp"
	"strings"
)

func init() {
	Common.AddBugScanListPerFolder(BackupFolderScan{Common.PluginBase{Name: "BackupFolderScan", Desc: "备份文件信息泄露", Type: "FolderScan", Level: 1}})
}

type BackupFolderScan struct {
	Common.PluginBase
}

func (p BackupFolderScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()
}
func (p BackupFolderScan) Audit() {
	file_dic := []string{"bak.rar", "bak.zip", "backup.rar", "backup.zip", "www.zip", "www.rar", "web.rar", "web.zip",
		"wwwroot.rar",
		"wwwroot.zip", "log.zip", "log.rar"}
	url := p.Request.CheckUrl.Scheme + "://" + p.Request.CheckUrl.Host + p.Request.CheckUrl.EscapedPath()
	domain := p.Request.CheckUrl.Host

	if m, _ := regexp.MatchString("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}.[0-9]{1,3}$", domain); !m {
		file_dic = append(file_dic, domain+".zip")
		file_dic = append(file_dic, domain+".rar")
		domainList := strings.Split(domain, ".")
		for _, domainSp := range domainList {
			if domainSp != "www" && domainSp != "web" && domainSp != "log" {
				file_dic = append(file_dic, domainSp+".zip")
				file_dic = append(file_dic, domainSp+".rar")
				file_dic = append(file_dic, domainSp+".bak")

			}
		}
	}

	for _, dic := range file_dic {
		url1 := url + dic
		result := Ghttp.Analyze(url1, "HEAD", "", nil, 5)
		if result.StatusCode == 200 {
			if strings.Contains(result.ContentType, "application/octet-stream") || strings.Contains(result.ContentType, "application/zip") {
				p.Success(p.Name, url1, p.Type, p.Desc, "")
			}
		}
	}
}
