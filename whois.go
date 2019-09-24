package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

var lastreq time.Time

var whoiscache map[string]*WhoisRecord

func init() {
	whoiscache = make(map[string]*WhoisRecord)
}

type WhoisRecord struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	Msg     string `json:"message"`
}

func WhoisLookup(ipport string) *WhoisRecord {
	ip, _, err := net.SplitHostPort(ipport)
	if err != nil {
		panic(err)
	}
	cached, ok := whoiscache[ip]
	if ok {
		return cached
	}
	if time.Now().Sub(lastreq) < 50*time.Millisecond {
		time.Sleep(50 * time.Millisecond)
	}
	target := "http://ip-api.com/json/" + ip
	response, err := http.Get(target)
	if err != nil {
		panic(err)
	}
	lastreq = time.Now()
	defer response.Body.Close()
	bodybin, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	rv := &WhoisRecord{}
	err = json.Unmarshal(bodybin, rv)
	if err != nil {
		panic(err)
	}
	if rv.Status != "success" {
		rv.Country = "?"
		rv.Region = "?"
		rv.City = "?"
		rv.ISP = "?"
		rv.Org = "?"
		rv.AS = "?"
	}
	whoiscache[ip] = rv
	return rv
}
