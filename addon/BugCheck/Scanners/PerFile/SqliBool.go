package PerFile

import (
	"encoding/json"
	"fmt"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/Ginfo/Ghttp"
	"math/rand"
	"strings"
	"sync"
	"time"
)

func SimilarText(first, second string, percent *float64) int {
	var similarText func(string, string, int, int) int
	similarText = func(str1, str2 string, len1, len2 int) int {
		var sum, max int
		pos1, pos2 := 0, 0

		// Find the longest segment of the same section in two strings
		for i := 0; i < len1; i++ {
			for j := 0; j < len2; j++ {
				for l := 0; (i+l < len1) && (j+l < len2) && (str1[i+l] == str2[j+l]); l++ {
					if l+1 > max {
						max = l + 1
						pos1 = i
						pos2 = j
					}
				}
			}
		}

		if sum = max; sum > 0 {
			if pos1 > 0 && pos2 > 0 {
				sum += similarText(str1, str2, pos1, pos2)
			}
			if (pos1+max < len1) && (pos2+max < len2) {
				s1 := []byte(str1)
				s2 := []byte(str2)
				sum += similarText(string(s1[pos1+max:]), string(s2[pos2+max:]), len1-pos1-max, len2-pos2-max)
			}
		}

		return sum
	}

	l1, l2 := len(first), len(second)
	if l1+l2 == 0 {
		return 0
	}
	sim := similarText(first, second, l1, l2)
	if percent != nil {
		*percent = float64(sim*200) / float64(l1+l2)
	}
	return sim
}

var sqlBoolPayload []string

func init() {
	sqliBoolScan := SqliBoolScan{Common.PluginBase{Name: "Sql注入Bool盲注", Desc: "存在Sql注入Bool盲注", Type: "SQL注入", Ltype: "", TimeOut: 5, Level: 5},
		3, &sync.Mutex{}}
	Common.AddBugScanListPerFile(sqliBoolScan)
	sqlBoolPayload = []string{
		//"<--isdigit-->",
		"/**/and %d=%d",
		"/**/and+%d=%d",
		"/**/and '%d'='%d",
		"' and'%d'='%d",
		"\" and\"%d\"=\"%d",
		" and '%d'='%d-- ",
		"' and '%d'='%d-- ",
		"\" and '%d'='%d-- ",
		") and '%d'='%d-- ",
		"') and '%d'='%d-- ",
		"\") and '%d'='%d-- ",
	}

}

type SqliBoolScan struct {
	Common.PluginBase
	CheckSum int
	Metux    *sync.Mutex
}

func (p SqliBoolScan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	//p.SleepTimeOut=5
	p.Request = request
	p.Response = response
	p.Audit()
}

type CheckBoolPayload struct {
	TruePayload  string
	FalsePayload string
}

func (p SqliBoolScan) Audit() {

	ratio := 0.0
	count := 0

	contentType_check := p.Request.Header.Get("Content-Type")
	// 目前该类型不做处理
	if strings.Contains(contentType_check, "multipart/form-data") {
		return
	}
	for ratio < 98 {
		if count > p.CheckSum {
			return
		}
		count++
		result_first := Ghttp.Analyze(p.Request.CheckUrl.String(), p.Request.Method, string(p.Request.Body), p.Request.Header, p.TimeOut)
		if result_first.StatusCode == p.Response.StatusCode {
			SimilarText(string(p.Response.Body), string(result_first.Body), &ratio)
		}
	}

	ct := time.Now() //代表当前时间的time对象
	ts := ct.Unix()  //unix时间戳
	//利用时间戳设置rand的种子数
	rand.Seed(ts)
	for _, sql := range sqlBoolPayload {
		if p.checkBoolSqli(sql) {
			return
		}
	}
}

func (p SqliBoolScan) checkBoolSqli(sql string) bool {
	if p.Request.Method == "GET" && p.Request.URL.RawQuery != "" {
		requestVuls := p.Request.CheckUrl.Query()
		for k1, _ := range requestVuls {
			v1 := requestVuls.Get(k1)

			checkCount := 0
			for i := 0; i < p.CheckSum; i++ {
				t1 := rand.Intn(9999)
				t2 := t1 + 5
				checkBoolPayload := CheckBoolPayload{}
				checkBoolPayload.TruePayload = fmt.Sprintf(sql, t1, t1)
				checkBoolPayload.FalsePayload = fmt.Sprintf(sql, t1, t2)

				requestVuls.Set(k1, v1+checkBoolPayload.TruePayload)
				p.Request.CheckUrl.RawQuery = requestVuls.Encode()
				println(p.Request.CheckUrl.String())
				resultTrue := Ghttp.Analyze(p.Request.CheckUrl.String(), "GET", "", p.Request.Header, p.TimeOut)
				ratioTraue := 0.0
				if resultTrue.StatusCode == p.Response.StatusCode {
					SimilarText(string(p.Response.Body), resultTrue.Body, &ratioTraue)
				}
				if ratioTraue < 98 {
					return false
				}
				requestVuls.Set(k1, v1+checkBoolPayload.FalsePayload)
				p.Request.CheckUrl.RawQuery = requestVuls.Encode()
				resultFalse := Ghttp.Analyze(p.Request.CheckUrl.String(), "GET", "", p.Request.Header, p.TimeOut)
				ratioFalse := 0.0
				if resultTrue.StatusCode == p.Response.StatusCode {
					SimilarText(string(p.Response.Body), resultFalse.Body, &ratioFalse)
				}
				ratioCheck := 0.0
				if resultTrue.StatusCode == p.Response.StatusCode {
					SimilarText(string(resultTrue.Body), resultFalse.Body, &ratioCheck)
				}
				if ratioCheck > 99 {
					return false
				}
				if ratioFalse >= 98 {
					return false
				}
				checkCount++
				requestVuls.Set(k1, v1)
			}

			if checkCount == p.CheckSum {
				p.Success(p.Name, p.Request.URL.String(), p.Type, sql, requestVuls.Encode())
				//目前是发现注入点就退出，不继续寻找下一个注入点
				return true
			}
		}

	}
	if p.Request.Method != "GET" && len(p.Request.Body) > 0 {
		contentType := p.Request.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/x-www-form-urlencoded") || !strings.Contains(contentType, "application/json") {
			p.Request.CheckUrl.RawQuery = string(p.Request.Body)
			requestVuls := p.Request.CheckUrl.Query()
			for k1, _ := range requestVuls {
				v1 := requestVuls.Get(k1)

				checkCount := 0
				for i := 0; i < p.CheckSum; i++ {
					t1 := rand.Intn(9999)
					t2 := t1 + 5
					checkBoolPayload := CheckBoolPayload{}
					checkBoolPayload.TruePayload = fmt.Sprintf(sql, t1, t1)
					checkBoolPayload.FalsePayload = fmt.Sprintf(sql, t1, t2)

					requestVuls.Set(k1, v1+checkBoolPayload.TruePayload)
					p.Request.CheckUrl.RawQuery = requestVuls.Encode()
					resultTrue := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, requestVuls.Encode(), p.Request.Header, p.TimeOut)
					ratioTraue := 0.0
					if resultTrue.StatusCode == p.Response.StatusCode {
						SimilarText(string(p.Response.Body), resultTrue.Body, &ratioTraue)
					}
					if ratioTraue < 98 {
						return false
					}

					requestVuls.Set(k1, v1+checkBoolPayload.FalsePayload)
					p.Request.CheckUrl.RawQuery = requestVuls.Encode()
					resultFalse := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, requestVuls.Encode(), p.Request.Header, p.TimeOut)
					ratioFalse := 0.0
					if resultTrue.StatusCode == p.Response.StatusCode {
						SimilarText(string(p.Response.Body), resultFalse.Body, &ratioFalse)
					}
					ratioCheck := 0.0
					if resultTrue.StatusCode == p.Response.StatusCode {
						SimilarText(string(resultTrue.Body), resultFalse.Body, &ratioCheck)
					}
					if ratioCheck > 99 {
						return false
					}
					if ratioFalse >= 98 {
						return false
					}
					checkCount++
					requestVuls.Set(k1, v1)
				}

				if checkCount == p.CheckSum {
					p.Success(p.Name, p.Request.URL.String(), p.Type, sql, requestVuls.Encode())
					//目前是发现注入点就退出，不继续寻找下一个注入点
					return true
				}

			}

		} else if strings.Contains(contentType, "application/json") {
			var f interface{}
			json.Unmarshal(p.Request.Body, &f)
			if f == nil {
				return false
			}
			m := f.(map[string]interface{})
			for k1, v1 := range m {
				switch v1.(type) {
				case string:

					vvv1 := v1
					checkCount := 0
					paylaod := ""
					for i := 0; i < p.CheckSum; i++ {
						t1 := rand.Intn(9999)
						t2 := t1 + 5
						checkBoolPayload := CheckBoolPayload{}
						checkBoolPayload.TruePayload = fmt.Sprintf(sql, t1, t1)
						checkBoolPayload.FalsePayload = fmt.Sprintf(sql, t1, t2)

						m[k1] = v1.(string) + checkBoolPayload.TruePayload
						bodymTrue, _ := json.Marshal(m)

						resultTrue := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(bodymTrue), p.Request.Header, p.TimeOut)
						ratioTraue := 0.0
						if resultTrue.StatusCode == p.Response.StatusCode {
							SimilarText(string(p.Response.Body), resultTrue.Body, &ratioTraue)
						}
						if ratioTraue < 98 {
							return false
						}
						vvv2 := vvv1
						m[k1] = vvv2
						m[k1] = vvv2.(string) + checkBoolPayload.FalsePayload
						bodymFalse, _ := json.Marshal(m)

						resultFalse := Ghttp.Analyze(p.Request.URL.String(), p.Request.Method, string(bodymFalse), p.Request.Header, p.TimeOut)
						ratioFalse := 0.0
						if resultTrue.StatusCode == p.Response.StatusCode {
							SimilarText(string(p.Response.Body), resultFalse.Body, &ratioFalse)
						}
						ratioCheck := 0.0
						if resultTrue.StatusCode == p.Response.StatusCode {
							SimilarText(string(resultTrue.Body), resultFalse.Body, &ratioCheck)
						}
						if ratioCheck > 99 {
							return false
						}
						if ratioFalse >= 98 {
							return false
						}
						paylaod = string(bodymFalse)
						checkCount++
						m[k1] = vvv1
					}
					if checkCount == p.CheckSum {

						p.Success(p.Name, p.Request.URL.String(), p.Type, sql, paylaod)
						//目前是发现注入点就退出，不继续寻找下一个注入点
						return true
					}
				case int:
				case float64:
				case []interface{}:
				default:
				}
			}
		}
	}
	return false

}
