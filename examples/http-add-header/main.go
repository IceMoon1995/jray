package main

import (
	"strconv"

	log "github.com/sirupsen/logrus"

	"jray/addon"
	"jray/flow"
	"jray/proxy"
)

type AddHeader struct {
	addon.Base
	count int
}

func (a *AddHeader) Responseheaders(f *flow.Flow) {
	a.count += 1
	f.Response.Header.Add("x-count", strconv.Itoa(a.count))
}

func main() {
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	p.AddAddon(&AddHeader{})

	log.Fatal(p.Start())
}
