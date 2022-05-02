package Common

import "jray/common"

type PluginBase struct {
	Name     string
	Desc     string
	Type     string
	Level    int
	Request  Request
	Response Response
	TimeOut  float32
}

type PluginBaseFun interface {
	GetName() string
	Audit()
	Exec(p1 PluginBaseFun, request Request, response Response)
	Success(name string, url string, Type string, detail string, result string)
}

func (p PluginBase) Audit() {
	println("Audit_A")
}
func (p PluginBase) GetName() string {
	return p.Name
}
func (p PluginBase) Success(name string, url string, Type string, detail string, result string) {
	common.LogError("\n[+] [" + Type + "] " + url + " " + name + " " + detail + " " + result)
}

func (p PluginBase) Exec(p1 PluginBaseFun, request Request, response Response) {
	p.Request = request
	p.Response = response
	p1.Audit()
}
