package BugCheck

import (
	"fmt"
	"jray/common"

	"jray/addon/BugCheck/Common"
	_ "jray/addon/BugCheck/Scanners/PerFile"
	_ "jray/addon/BugCheck/Scanners/PerFile/JS"
	_ "jray/addon/BugCheck/Scanners/PerFile/Java"
	_ "jray/addon/BugCheck/Scanners/PerFolder"
	_ "jray/addon/BugCheck/Scanners/PerServer"

	"jray/flow"
	"strings"
	"sync"
	"time"
)

type Counter struct {
	AllNum   uint64
	CheckNum uint64
	EndNum   uint64
}

type ChekStruts struct {
	Fun      *Common.PluginBaseFun
	Request  *Common.Request
	Response *Common.Response
}

type BugCheckAddon struct {
	connsMu                     sync.RWMutex
	CheckListWait               []flow.Flow
	CheckListSend               []Common.PluginBaseFun
	CheckListEnd                []flow.Flow
	CheckListPerFileIsChecked   []string
	CheckListPerFolderIsChecked []string
	CheckListPerServerIsChecked []string
	WorkerCount                 int
	Mutex                       *sync.Mutex
	TaskChan                    chan ChekStruts
	Counter                     Counter
}

func (bugCheck *BugCheckAddon) CheckPerFileRun(flow2 flow.Flow) {
	//defer wg.Done()
	isCheck := false
	for _, sttt := range bugCheck.CheckListPerFileIsChecked {
		if flow2.Request.URL.Scheme+"://"+flow2.Request.URL.Host+flow2.Request.URL.EscapedPath() == sttt {
			isCheck = true
		}
	}
	if isCheck {
		return
	}
	bugCheck.CheckListPerFileIsChecked = append(bugCheck.CheckListPerFileIsChecked, flow2.Request.URL.Scheme+"://"+flow2.Request.URL.Host+flow2.Request.URL.EscapedPath())

	request := Common.Request{}
	request.Header = flow2.Request.Header
	request.Body = flow2.Request.Body
	request.URL = *flow2.Request.URL
	request.Proto = flow2.Request.Proto
	request.Method = flow2.Request.Method
	request.CheckUrl = *flow2.Request.URL

	contentType := request.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		//println(contentType)
		return
	}
	response := Common.Response{}
	response.Header = flow2.Response.Header
	response.Body = flow2.Response.Body
	response.StatusCode = flow2.Response.StatusCode

	if strings.HasSuffix(request.URL.EscapedPath(), ".js") || strings.HasSuffix(request.URL.EscapedPath(), ".map") {
		for _, scan2 := range Common.BugScanListPerFileJs {
			scan := scan2
			if scan.GetLevel() <= common.CheckLevel {
				request2 := request
				response2 := response
				bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
				bugCheck.Counter.AllNum++
			}
		}
	} else {
		for _, scan2 := range Common.BugScanListPerFile {
			scan := scan2
			if scan.GetLevel() <= common.CheckLevel {
				request2 := request
				response2 := response
				if strings.HasSuffix(request.URL.EscapedPath(), ".action") || strings.HasSuffix(request.URL.EscapedPath(), ".jsp") || strings.HasSuffix(request.URL.EscapedPath(), ".jspx") {
					if scan.GetLtype() == "" || scan.GetLtype() == "JAVA" {
						bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
						bugCheck.Counter.AllNum++
					}
				} else if strings.HasSuffix(request.URL.EscapedPath(), ".asp") || strings.HasSuffix(request.URL.EscapedPath(), ".aspx") {
					if scan.GetLtype() == "" || scan.GetLtype() == "ASP" {
						bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
						bugCheck.Counter.AllNum++
					}
				} else if strings.HasSuffix(request.URL.EscapedPath(), ".php") {
					if scan.GetLtype() == "" || scan.GetLtype() == "PHP" {
						bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
						bugCheck.Counter.AllNum++
					}
				} else {
					bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
					bugCheck.Counter.AllNum++
				}
			}
		}
	}

	return
}
func (bugCheck *BugCheckAddon) CheckPerFolderRun(flow2 flow.Flow) {
	//defer wg.Done()

	request := Common.Request{}
	request.Header = flow2.Request.Header
	request.Body = flow2.Request.Body
	request.Proto = flow2.Request.Proto
	request.Method = flow2.Request.Method
	response := Common.Response{}
	response.Header = flow2.Response.Header
	response.Body = flow2.Response.Body
	response.StatusCode = flow2.Response.StatusCode

	request.URL = *flow2.Request.URL
	request.CheckUrl = *flow2.Request.URL
	folderes := strings.Split(request.CheckUrl.Path, "/")
	folderes = folderes[:len(folderes)-1]
	urll := ""
	for _, folderes := range folderes {
		urll = urll + folderes + "/"
		request.CheckUrl.Path = urll
		isCheck := false
		for _, sttt := range bugCheck.CheckListPerFolderIsChecked {
			if request.CheckUrl.Scheme+"://"+request.CheckUrl.Host+request.CheckUrl.EscapedPath() == sttt {
				isCheck = true
			}
		}
		if isCheck {
			return
		}

		bugCheck.CheckListPerFolderIsChecked = append(bugCheck.CheckListPerFolderIsChecked, request.CheckUrl.Scheme+"://"+request.CheckUrl.Host+request.CheckUrl.EscapedPath())

		for _, scan2 := range Common.BugScanListPerFolder {
			scan := scan2
			if scan.GetLevel() <= common.CheckLevel {

				request2 := request
				response2 := response
				bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
				bugCheck.Counter.AllNum++
			}
		}
	}
	return
}
func (bugCheck *BugCheckAddon) CheckPerServerRun(flow2 flow.Flow) {
	//defer wg.Done()

	isCheck := false
	for _, sttt := range bugCheck.CheckListPerServerIsChecked {
		if flow2.Request.URL.Scheme+"://"+flow2.Request.URL.Host == sttt {
			isCheck = true
		}
	}
	if isCheck {
		return
	}
	bugCheck.CheckListPerServerIsChecked = append(bugCheck.CheckListPerServerIsChecked, flow2.Request.URL.Scheme+"://"+flow2.Request.URL.Host)
	request := Common.Request{}
	request.Header = flow2.Request.Header
	request.Body = flow2.Request.Body
	request.URL = *flow2.Request.URL
	request.Proto = flow2.Request.Proto
	request.Method = flow2.Request.Method
	request.CheckUrl = *flow2.Request.URL
	request.CheckUrl.Path = "/"

	response := Common.Response{}
	response.Header = flow2.Response.Header
	response.Body = flow2.Response.Body
	response.StatusCode = flow2.Response.StatusCode

	for _, scan2 := range Common.BugScanListPerFServer {
		scan := scan2
		if scan.GetLevel() <= common.CheckLevel {
			request2 := request
			response2 := response
			bugCheck.TaskChan <- ChekStruts{&scan, &request2, &response2}
			bugCheck.Counter.AllNum++
		}
	}
	return
}

func Worker(funs chan ChekStruts, counter *Counter, mtx *sync.Mutex) {
	go func() {
		for fun := range funs {
			mtx.Lock()
			counter.CheckNum++
			mtx.Unlock()
			//do netbios stat scan
			(*fun.Fun).Exec(*fun.Fun, *fun.Request, *fun.Response)
			mtx.Lock()
			counter.CheckNum--
			counter.EndNum++
			mtx.Unlock()

		}
	}()
}

func (bugCheck *BugCheckAddon) CheckRun() {
	for i := 0; i < bugCheck.WorkerCount; i++ {
		Worker(bugCheck.TaskChan, &bugCheck.Counter, bugCheck.Mutex)
	}
	for true {
		if len(bugCheck.CheckListWait) > 0 {
			request := bugCheck.CheckListWait[0]
			ends_with := []string{".png", ".jpg", ".gif", ".css", ".woff", ".zip", ".rar", ".7z", ".pdf", ".vue",
				".jpeg", ".class", ".ico", ".png", ".bmp",
				".woff",
				".woff2",
				".ttf",
				".otf",
				".ttc",
				".svg",
				".psd",
				".exe",
				".msi",
				".tar",
				".gz",
				".mp3",
				".mp4",
				".mkv",
				".swf",
				".xls",
				".xlsx",
				".doc",
				".docx",
				".ppt",
				".pptx",
				".iso"}
			isSourceFile := false
			for _, end := range ends_with {
				if strings.HasSuffix(request.URL.EscapedPath(), end) {
					isSourceFile = true
					break
				}
			}
			if isSourceFile {
				bugCheck.CheckListWait = bugCheck.CheckListWait[1:]
				continue
			}

			bugCheck.CheckPerFileRun(request)
			bugCheck.CheckPerFolderRun(request)
			bugCheck.CheckPerServerRun(request)
			bugCheck.CheckListWait = bugCheck.CheckListWait[1:]
		} else {
			time.Sleep(800 * time.Millisecond)
		}
		fmt.Printf("\r %d success | %d running | %d remaining | %d scanned", bugCheck.Counter.EndNum, bugCheck.Counter.CheckNum, bugCheck.Counter.AllNum-bugCheck.Counter.CheckNum-bugCheck.Counter.EndNum, bugCheck.Counter.AllNum)
	}
	return
}

func (bugCheck *BugCheckAddon) Requestheaders(f *flow.Flow) {
	return
}

func (bugCheck *BugCheckAddon) Request(f *flow.Flow) {
	return
}

func (bugCheck *BugCheckAddon) Responseheaders(f *flow.Flow) {
	return
}

func (bugCheck *BugCheckAddon) Response(f *flow.Flow) {
	if !common.IsCheck {
		bugCheck.CheckListWait = append(bugCheck.CheckListWait, *f)
	}
	//println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	//println(f.Request.Method)
	//println(f.Request.URL.Host)
	//println(f.Request.URL.Path)
	//println(f.Request.URL.RequestURI())
	//println(f.Request.URL.RawQuery)
	//println(string(f.Request.Body))
	//println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
}
