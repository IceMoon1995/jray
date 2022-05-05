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
	Ltype    string //语言类型，JAVA PHP ASP 等 用于漏洞检测分裂
	//UseReverse bool
}

type PluginBaseFun interface {
	GetName() string
	GetLtype() string
	Audit()
	Exec(p1 PluginBaseFun, request Request, response Response)
	Success(name string, url string, Type string, detail string, result string)
	CheckReverse() bool
	GetReverseType() string
}

func (p PluginBase) GetReverseType() string {
	return common.UseReverseType
}
func (p PluginBase) CheckReverse() bool {
	return common.IsUseReverse
}

func (p PluginBase) Audit() {
	println("Audit_A")
}
func (p PluginBase) GetLtype() string {
	return p.Ltype
}
func (p PluginBase) GetName() string {
	return p.Name
}
func (p PluginBase) Success(name string, url string, Type string, detail string, result string) {
	common.LogSuccess("\n[+] [" + Type + "] " + url + " " + name + " " + detail + " " + result)
}

func (p PluginBase) Exec(p1 PluginBaseFun, request Request, response Response) {
	p.Request = request
	p.Response = response
	p1.Audit()
}
