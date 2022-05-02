package WebScan

import (
	"embed"
	"fmt"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/WebScan/lib"
	"jray/common"
	"net/http"
)

//go:embed pocs
var Pocs embed.FS

func WebScan(request Common.Request, response Common.Response) {
	var pocinfo = Common.Pocinfo
	pocinfo.Request = request
	pocinfo.Response = response
	pocinfo.Target = request.CheckUrl.Scheme + "://" + request.CheckUrl.Host + request.CheckUrl.EscapedPath()
	CheckDatass := []CheckDatas{}
	CheckData := CheckDatas{}
	CheckData.Headers = fmt.Sprintf("%s", request.Header)
	CheckData.Body = request.Body
	CheckDatass = append(CheckDatass, CheckData)
	url := request.CheckUrl.Scheme + "://" + request.CheckUrl.Host + request.CheckUrl.EscapedPath()
	pocinfo.Infostr = InfoCheck(url, &CheckDatass)

	if pocinfo.PocName != "" {

		Execute(pocinfo)
	} else {
		for _, infostr := range pocinfo.Infostr {
			pocinfo.PocName = lib.CheckInfoPoc(infostr)
			Execute(pocinfo)
		}
	}
}

func Execute(PocInfo Common.PocInfo) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webpocinit %v %v", PocInfo.Target, err)
		common.LogError(errlog)
		return
	}
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	if PocInfo.Response.Header != nil {
		for k, _ := range PocInfo.Response.Header {
			req.Header.Set(k, PocInfo.Response.Header.Get(k))
		}
	}

	lib.CheckMultiPoc(req, Pocs, PocInfo.Num, PocInfo.PocName)
}
