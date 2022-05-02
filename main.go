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
	flag.BoolVar(&common.Ssl_insecure, "ssl_insecure", true, "not verify upstream server SSL/TLS certificates.")
	flag.StringVar(&common.Dump, "dump", "jweb.txt", "dump filename")
	flag.IntVar(&common.DumpLevel, "dump_level", 1, "dump level: 0 - header, 1 - header + body")
	flag.StringVar(&common.MapperDir, "mapper_dir", "", "mapper files dirpath")
	flag.StringVar(&common.CertPath, "cert_path", "", "path of generate cert files")
	flag.BoolVar(&common.IsSave, "nosave", true, "是否保存扫描结果")
	flag.StringVar(&common.Outputfile, "o", "result_vul.txt", "扫描结果保存的文件名")
	flag.IntVar(&common.ScanThreads, "t", 16, "扫描并发数")

	flag.Parse()
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
		SslInsecure:       common.Ssl_insecure,
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
