package PerFolder

import (
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/WebScan"
)

func init() {
	Common.AddBugScanListPerFServer(YmlPocCheckScan{Common.PluginBase{Name: "YmlPocCheckScan", Desc: "YmlPocCheckScan", Type: "ServerScan", Level: 1}})
}

type YmlPocCheckScan struct {
	Common.PluginBase
}

func (p YmlPocCheckScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()

}
func (p YmlPocCheckScan) Audit() {
	WebScan.WebScan(p.Request, p.Response)
}
