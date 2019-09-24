package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/immesys/sshtool"
	"gopkg.in/mgo.v2"
)

type Router struct {
	IP      string
	User    string
	Keyfile string
}

func main() {
	r := Router{
		IP:      "192.168.1.1",
		User:    "admin",
		Keyfile: "/home/michael/.ssh/id_rsa",
	}
	if len(os.Args) < 2 {
		fmt.Printf("usage: autowall train/process\n")
		os.Exit(1)
	}
	InitializeOUIs()
	if os.Args[1] == "train" {
		go r.TrainWifiClients()
		go r.TrainDHCP()
		go r.TrainConnections()
		go r.TrainArp()
		for {
			time.Sleep(10 * time.Second)
		}
	} else if os.Args[1] == "process" {
		r.Crunch()
	} else {
		fmt.Printf("unknown action\n")
		os.Exit(1)
	}
}

func (r *Router) exec(cmd string) (string, error) {
	sh, err := sshtool.NewSSHRunner(r.Keyfile, r.User, r.IP+":22")
	if err != nil {
		return "", err
	}
	ba, err := sh.RunNative(context.Background(), cmd)
	return string(ba), err
}
func (r *Router) Train(short, command, collection string) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	col := session.DB("autowall").C(collection)

	cd := strings.Replace(command, "\n", "", -1)
	start := time.Now()
	time.Sleep(time.Duration(rand.Int()%10) * time.Second)
	for {
		sampleid := fmt.Sprintf("%d", time.Now().Unix())
		rv, err := r.exec(cd)
		if err != nil {
			panic(err)
		}
		res, err := r.parseResult(rv)
		if err != nil {
			panic(err)
		}
		for _, entry := range res {
			entry["_sample"] = sampleid
			err := col.Insert(entry)
			if err != nil {
				panic(err)
			}
		}
		nextSample := start.Add(30 * time.Second)
		diff := nextSample.Sub(time.Now())
		if diff > 0 {
			start = nextSample
			fmt.Printf("[%s] ACQUIRED! Sleeping for %s\n", short, diff)
			time.Sleep(diff)
		} else {
			start = time.Now()
			fmt.Printf("[%s] skipping sleep\n", short)
		}
	}
}
func (r *Router) TrainWifiClients() {
	r.Train("wificlients", wifiData, "wificlients")
}
func (r *Router) TrainArp() {
	r.Train("arp", arpData, "arp")
}
func (r *Router) TrainConnections() {
	r.Train("connections", connData, "connections")
}
func (r *Router) TrainDHCP() {
	r.Train("dhcp", dhcpData, "dhcp")
}

func (r *Router) parseResult(s string) ([]map[string]string, error) {
	lines := strings.Split(s, "\n")
	rv := []map[string]string{}
	for _, ln := range lines {
		thisline := make(map[string]string)
		thisline["_line"] = ln
		//fmt.Printf("line: %v\n", ln)
		parts := strings.Split(ln, ";")
		nonempty := []string{}
		for _, p := range parts {
			if len(p) == 0 {
				continue
			}
			nonempty = append(nonempty, p)
		}
		for _, p := range nonempty {
			kv := strings.Split(p, "=")
			if kv[0] == "discard" {
				continue
			}
			thisline[kv[0]] = kv[1]
			/*	if kv[1] == "" {
				fmt.Printf("hold the phone, line was:n%s\np was:%s\nthe page was:\n%s\n", ln, p, s)
				os.Exit(1)
			}*/
		}
		if len(thisline) == 0 {
			continue
		}
		rv = append(rv, thisline)
	}
	return rv, nil
}

const connData = `/ip firewall connection {:foreach i in=[find] do={
:put (
	"seenreply=". [get $i seen-reply].
	";assured=". [get $i assured].
	";confirmed=". [get $i confirmed].
	";dying=". [get $i dying].
	";fasttrack=". [get $i fasttrack].
	";srcnat=". [get $i srcnat].
	";dstnat=". [get $i dstnat].
	";protocol=". [get $i protocol].
	";srcaddress=". [get $i src-address].
	";srcaddressnoport=". [:pick [get $i src-address] 0 [:find [get $i src-address] ":"]].
	";dstaddress=". [get $i dst-address].
	";replysrcaddress=". [get $i reply-src-address].
	";replydstaddress=". [get $i reply-dst-address].
	";timeout=". [get $i timeout].
	";tcpstate=". [get $i tcp-state].
	";origpackets=". [get $i orig-packets].
	";origbytes=". [get $i orig-bytes].
	";origfastpackets=". [get $i orig-fasttrack-packets].
	";origfastbytes=". [get $i orig-fasttrack-bytes].
	";replypackets=". [get $i repl-packets].
	";replybytes=". [get $i repl-bytes].
	";replyfastpackets=". [get $i repl-fasttrack-packets].
	";replyfastbytes=". [get $i repl-fasttrack-bytes].
	";origrate=". [get $i orig-rate].
	";replyrate=". [get $i repl-rate].
	";discard="
	);}}`

const wifiData = `/interface wireless registration-table {:foreach i in=[find] do={
:put (
	"interface=". [get $i interface].
	";macaddr=". [get $i mac-address].
	";packets=". [get $i packets].
	";bytes=". [get $i bytes].
	";uptime=". [get $i uptime].
	";lastactivity=". [get $i last-activity].
	";lastip=". [get $i last-ip].
	";txrate=". [get $i tx-rate].
	";rxrate=". [get $i rx-rate].
	";discard="
	);}}`

/*
	address=192.168.1.111 mac-address=AC:37:43:51:53:94 client-id="1:ac:37:43:51:53:94" address-lists="" server=defconf always-broadcast=yes dhcp-option="" status=bound
	     expires-after=8m28s last-seen=1m32s active-address=192.168.1.111 active-mac-address=AC:37:43:51:53:94 active-client-id="1:ac:37:43:51:53:94" active-server=defconf
	     host-name="android-cd0671943e5a07c1" */

const dhcpData = `/ip dhcp-server lease {:foreach i in=[find] do={
:put (
	"address=". [get $i address].
	";macaddr=". [get $i mac-address].
	";status=". [get $i status].
	";expires=". [get $i expires-after].
	";lastseen=". [get $i last-seen].
	";activeaddress=". [get $i active-address].
	";activemacaddress=". [get $i active-mac-address].
	";hostname=". [get $i host-name].
	";discard="
	);}}`

const arpData = `/ip arp {:foreach i in=[find] do={
:put (
	"address=". [get $i address].
	";macaddr=". [get $i mac-address].
	";discard="
	);}}`

/*

 */
/*
/ip firewall filter {:foreach i in=[find] do={:put ("item=". [get $i comment]." bytes=".[get $i bytes]." packets=".[get $i bytes]);}}
*/
