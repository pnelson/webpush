package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/pnelson/webpush"
)

var (
	h       = flag.Bool("h", false, "show this usage information")
	o       = flag.String("o", "vapid.pem", "output filename for gen-keys flag")
	genKeys = flag.Bool("gen-keys", false, "generate webpush keys")
)

func init() {
	log.SetFlags(0)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]... [CHANNEL]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	if *h {
		flag.Usage()
		return
	}
	if !*genKeys {
		flag.Usage()
		os.Exit(1)
	}
	if *o == "" {
		*o = "vapid.pem"
	}
	b, err := webpush.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(*o, b, 0640)
	if err != nil {
		log.Fatal(err)
	}
}
