package main

import (
	"encoding/csv"
	"io"
	"os"
	"strings"
)

var ouitable map[string]string

func InitializeOUIs() {
	ouitable = make(map[string]string)
	addToTable("oui0.csv")
	addToTable("oui1.csv")
	addToTable("oui2.csv")
}

func addToTable(registry string) {
	f0, err := os.Open("oui0.csv")
	if err != nil {
		panic(err)
	}
	defer f0.Close()
	rdr := csv.NewReader(f0)
	for {
		rec, err := rdr.Read()
		if err == io.EOF {
			return
		}
		ass := rec[1]
		mfg := rec[2]
		ouitable[ass] = mfg
	}
}

func lookupMac(mac string) string {
	key := strings.Replace(mac, ":", "", -1)
	for i := len(key); i >= 2; i-- {
		prefix := key[:i]
		rv, ok := ouitable[prefix]
		if ok {
			return rv
		}
	}
	return "unknown"
}
