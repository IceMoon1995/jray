package PerFile

import (
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"strings"
	"sync"
)

func init() {
	unauthScan := UnauthScan{Common.PluginBase{Name: "未授权访问", Desc: "存在未授权访问漏洞", Type: "unauth", Ltype: "", TimeOut: 5, Level: 1},
		2, &sync.Mutex{}}
	Common.AddBugScanListPerFile(unauthScan)

}

type UnauthScan struct {
	Common.PluginBase
	CheckSum int
	Metux    *sync.Mutex
}

func (p UnauthScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	//p.SleepTimeOut=5
	p.Request = request
	p.Response = response
	p.Audit()
}

func (p UnauthScan) Audit() {

	ratio := 0.0

	contentType_check := p.Request.Header.Get("Content-Type")
	// 目前该类型不做处理
	if strings.Contains(contentType_check, "multipart/form-data") {
		return
	}
	historyBody := string(p.Response.Body)
	//暂时不检查<html>未授权
	if p.Response.StatusCode != 200 || len(historyBody) < 10 || strings.Contains(historyBody, "</html>") || strings.Contains(historyBody, "Unauthorized") || strings.Contains(historyBody, "未授权") || strings.Contains(historyBody, "<html>") {
		return
	}
	urll := p.Request.URL.Path
	param := p.Request.URL.RawQuery
	urll = strings.ToLower(urll)
	param = strings.ToLower(param)

	if strings.Contains(strings.ToLower(urll), "login") || strings.Contains(urll, "index") || strings.Contains(urll, "main") || strings.Contains(urll, "home") {
		return
	}
	//get参数包含session，token的，目前不检测
	if strings.Contains(strings.ToLower(param), "session") || strings.Contains(param, "token") {
		return
	}
	doCheck := false
	for k, _ := range p.Request.Header {
		if strings.Contains(k, "cookie") || strings.Contains(k, "token") || strings.Contains(k, "auth") || strings.Contains(k, "authorization") {
			p.Request.Header.Set(k, "1")

			doCheck = true
		}
	}
	if doCheck {
		result_first := Ghttp.Analyze(p.Request.CheckUrl.String(), p.Request.Method, string(p.Request.Body), p.Request.Header, p.TimeOut)
		if result_first.StatusCode == p.Response.StatusCode {
			SimilarText(string(p.Response.Body), string(result_first.Body), &ratio)
			if ratio > 95 {
				p.Success(p.Name, p.Request.URL.String(), p.Type, "", "")

			}
		}
	}

}
