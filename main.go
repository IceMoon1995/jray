package main

import (
	"flag"
	"fmt"
	"jray/addon/BugCheck"
	"jray/addon/BugCheck/Common"
	"jray/addon/BugCheck/WebScan/lib"
	"sync"

	// slog "log"

	log "github.com/sirupsen/logrus"
	"jray/addon"
	"jray/addon/flowmapper"
	"jray/addon/web"
	"jray/common"
	"jray/proxy"
	"os"
)

func loadConfig() {
	flag.BoolVar(&common.Version, "version", false, "show version")
	flag.StringVar(&common.Addr, "addr", "9080", "proxy listen addr")
	flag.StringVar(&common.WebAddr, "waddr", "9081", "web interface listen addr")
	flag.BoolVar(&common.Ssl_insecure, "ssl_insecure", false, "not verify upstream server SSL/TLS certificates.")
	flag.StringVar(&common.Dump, "dump", "jweb.txt", "dump filename")
	flag.IntVar(&common.DumpLevel, "dump_level", 1, "dump level: 0 - header, 1 - header + body")
	flag.IntVar(&common.CheckLevel, "ckeckLevel", 1, "bug检查级别")
	flag.BoolVar(&common.IsCheck, "nocheck", false, "是否进行扫描，不扫描则只进行")

	flag.StringVar(&common.MapperDir, "mapper_dir", "", "mapper files dirpath")
	flag.StringVar(&common.CertPath, "cert_path", "", "path of generate cert files")
	flag.BoolVar(&common.IsSave, "nosave", false, "是否保存扫描结果")
	flag.StringVar(&common.Outputfile, "o", "result_vul.txt", "扫描结果保存的文件名")
	flag.IntVar(&common.ScanThreads, "t", 20, "扫描并发数")
	flag.StringVar(&common.Proxy, "proxy", "", "上层代理设置 -proxy http://127.0.0.1:8887")
	flag.BoolVar(&common.IsUseReverse, "re", false, "是否启用反连平台")
	flag.StringVar(&common.UseReverseType, "ret", "ldap", "反连平台类型:DnsLog,ldap,rmi")
	flag.StringVar(&common.ReverseDomain, "reDomian", "127.0.0.1:1389", "反连平台地址")
	flag.StringVar(&common.ReverseCheckDomain, "reCDomain", "http://127.0.0.1:8080", "反连平台检测验证地址")
	flag.Parse()

	if common.IsUseReverse {
		if common.UseReverseType == "ldap" {
			reverse := Common.ReverseMap[common.UseReverseType]
			reverse.ReverseDomain = common.ReverseDomain
			reverse.ReverseCheckDomain = common.ReverseCheckDomain + "/%s.md5"
			Common.ReverseMap[common.UseReverseType] = reverse
		} else if common.UseReverseType == "dig" {
			digresult := Common.GetDNSLog_Platform_Golang("https://dig.pm")
			if digresult == nil {
				common.IsUseReverse = false
				println("dig平台未成功连接")
			} else {
				println("dig平台成功连接")

				reverse := Common.ReverseMap[common.UseReverseType]
				reverse.ReverseDomain = digresult["domain"]
				reverse.DigToken = digresult["token"]
				reverse.DigKey = digresult["key"]
				Common.ReverseMap[common.UseReverseType] = reverse

			}
		}

	}
}

func main() {
	loadConfig()
	common.Addr = ":" + common.Addr
	common.WebAddr = ":" + common.WebAddr

	log.SetLevel(log.PanicLevel)
	log.SetReportCaller(false)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: false,
	})

	//启动漏洞扫描初始化
	lib.Inithttp(Common.Pocinfo)

	opts := &proxy.Options{
		Addr:              common.Addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       !common.Ssl_insecure,
		CaRootPath:        common.CertPath,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	if common.Version {
		fmt.Println("jary: " + p.Version)
		os.Exit(0)
	}

	log.Error("jary version %v\n", p.Version)

	p.AddAddon(&addon.Log{})
	bugCheck := BugCheck.BugCheckAddon{WorkerCount: common.ScanThreads, Mutex: &sync.Mutex{}, TaskChan: make(chan BugCheck.ChekStruts, 10000)}
	p.AddAddon(&bugCheck)
	go bugCheck.CheckRun()

	p.AddAddon(web.NewWebAddon(common.WebAddr))

	if common.Dump != "" {
		dumper := addon.NewDumper(common.Dump, common.DumpLevel)
		p.AddAddon(dumper)
	}

	if common.MapperDir != "" {
		mapper := flowmapper.NewMapper(common.MapperDir)
		p.AddAddon(mapper)
	}

	log.Fatal(p.Start())
}
