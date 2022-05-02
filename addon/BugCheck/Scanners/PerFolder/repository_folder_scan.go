package PerFolder

import (
	"jray/addon/BugCheck/Common"
	"regexp"
)
import "jray/addon/BugCheck/Ginfo/Ghttp"

func init() {
	Common.AddBugScanListPerFolder(RepositoryFolderScan{Common.PluginBase{Name: "RepositoryFolderScan", Desc: "仓库信息泄露", Type: "FolderScan", Level: 1}})
}

type RepositoryFolderScan struct {
	Common.PluginBase
}

func (p RepositoryFolderScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()

}
func (p RepositoryFolderScan) Audit() {
	file_dic := map[string]string{".svn/all-wcprops": "svn:wc:ra_dav:version-url", ".git/config": "repositoryformatversion[\\s\\S]*", ".bzr/README": "This\\sis\\sa\\sBazaar[\\s\\S]", "CVS/Root": ":pserver:[\\s\\S]*?:[\\s\\S]*", ".hg/requires": "^revlogv1.*"}
	url := p.Request.CheckUrl.Scheme + "://" + p.Request.CheckUrl.Host + p.Request.CheckUrl.EscapedPath()
	for dic, v := range file_dic {
		url1 := url + dic
		result := Ghttp.Analyze(url1, "GET", "", nil, 5)
		if result.StatusCode == 200 {
			if m, _ := regexp.MatchString(v, result.Body); !m {
				continue
			}
			p.Success(p.Name, url1, p.Type, p.Desc, "")
		}
	}
}
