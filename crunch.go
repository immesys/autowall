package main

import (
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/davecgh/go-spew/spew"
	"github.com/fatih/color"

	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

func (r *Router) Crunch() {
	// session, err := mgo.Dial("localhost")
	// if err != nil {
	// 	panic(err)
	// }
	// conns := session.DB("autowall").C("connections")
	// dhcp := session.DB("autowall").C("dhcp")
	// wifi := session.DB("autowall").C("wificlients")
	// _ = wifi
	// _ = dhcp
	// _ = conns
	devices := GenerateDevices()
	_ = devices
	//rv := GenerateSessions("192.168.1.100")
	//spew.Dump(rv)
	//fmt.Printf("done: %v\n", rv)
	//Make a list of all the clients, indexed by MAC
	//for each one we will apply a policy
	// - internet-only
	// - spawnpoint-only
	// - spawn+internet
	// - local-only
	// - unrestricted

	// The user will pick based on
	// origin (2gz, 5gz, LAN)
	// hostname
	// MAC
	// manufacturer
	// IP address
	// Session info (top 5 destinations)
}

type Device struct {
	Origin   string
	Hostname string
	MAC      string
	Mfg      string
	IP       string
	IsDHCP   bool
	Sessions []Session
}

type Session struct {
	ToAddr   string
	ToHost   string
	Whois    *WhoisRecord
	Protocol string
	TXBytes  int64
	RXBytes  int64
}

type sesskey struct {
	Srcipport string
	Dstipport string
	Proto     string
}

func rlookup(dest string) string {
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		fmt.Printf("Dest was %q\n", dest)
		panic(err)
	}
	rv, err := net.LookupAddr(host)
	if err != nil || len(rv) == 0 {
		return dest
	}
	return rv[0]
}

func isPrivateIP(ipport string) bool {
	ip, _, err := net.SplitHostPort(ipport)
	if err != nil {
		panic(err)
	}
	private := false
	IP := net.ParseIP(ip)
	if IP == nil {
		fmt.Printf("ip was %v\n", ip)
		panic("invalid ip?")
	}
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
	return private
}

func GenerateDevices() []Device {
	//Do this based on DHCP data
	//Use WiFi data to infer origin
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	rvm := make(map[string]Device)
	//conns := session.DB("autowall").C("connections")
	dhcp := session.DB("autowall").C("dhcp")
	wifi := session.DB("autowall").C("wificlients")
	arp := session.DB("autowall").C("arp")
	var result map[string]string
	iter := dhcp.Find(bson.M{}).Sort("_sample").Iter()
	for iter.Next(&result) {
		key := result["address"]
		_, ok := rvm[key]
		if !ok {
			rvm[key] = Device{
				Hostname: result["hostname"],
				MAC:      result["macaddr"],
				IP:       result["address"],
				IsDHCP:   true,
			}
		}
	}
	iter.Close()

	//Ok use WiFi to try nail down on origin
	iter = wifi.Find(bson.M{}).Sort("_sample").Iter()
	for iter.Next(&result) {
		key := result["lastip"]
		if key == "" {
			continue
		}
		res, ok := rvm[key]
		origin := "wifi_2.4"
		if result["interface"] == "wlan2" {
			origin = "wifi_5"
		}
		if !ok {
			res = Device{
				Hostname: "not captured",
				MAC:      result["macaddr"],
				IP:       result["lastip"],
				IsDHCP:   false,
			}
		}
		res.Origin = origin
		rvm[key] = res
	}
	iter.Close()

	//Ok now get from ARP
	iter = arp.Find(bson.M{}).Sort("_sample").Iter()
	for iter.Next(&result) {
		key := result["address"]
		_, ok := rvm[key]
		if !ok {
			rvm[key] = Device{
				Hostname: "not captured",
				MAC:      result["macaddr"],
				IP:       result["address"],
				IsDHCP:   false,
			}
		}
	}
	iter.Close()

	//Now lets get srcip distincts
	conns := session.DB("autowall").C("connections")
	distinctips := []string{}
	err = conns.Find(bson.M{}).Distinct("srcaddressnoport", &distinctips)
	if err != nil {
		panic(err)
	}
	for _, ip := range distinctips {
		if len(ip) < 4 {
			//from ICMP
			continue
		}
		_, ok := rvm[ip]
		if !ok {
			fmt.Printf("found rogue host %q", ip)
			rvm[ip] = Device{
				Hostname: "not captured",
				MAC:      "not captured",
				IP:       ip,
				IsDHCP:   false,
			}
		}
	}
	//Ok we have all DHCP records. Find all observed IPs to try locate statics

	//Ok we can probably assume all records with origin unset are LAN
	for key, el := range rvm {
		if el.Origin == "" {
			el.Origin = "lan"
		}
		rvm[key] = el
	}

	//Now lets put the DHCP marking on the origins
	for key, el := range rvm {
		if el.IsDHCP {
			el.Origin += "/DHCP"
		} else {
			el.Origin += "/STATIC"
		}
		rvm[key] = el
	}

	//Ok lets look up the manufacturers
	for key, el := range rvm {
		mfg := lookupMac(el.MAC)
		el.Mfg = mfg
		rvm[key] = el
	}

	//Ok lets capture sessions now
	for key, el := range rvm {
		sdata := GenerateSessions(el.IP)
		if len(sdata) > 5 {
			sdata = sdata[:5]
		}
		for idx, s := range sdata {
			s.ToHost = rlookup(s.ToAddr)
			if !isPrivateIP(s.ToAddr) {
				s.Whois = WhoisLookup(s.ToAddr)
			}
			sdata[idx] = s
		}

		el.Sessions = sdata
		rvm[key] = el
	}
	//Ok now turn into list
	devlist := []Device{}

	for _, dev := range rvm {
		devlist = append(devlist, dev)
	}
	for idx, d := range devlist {
		presentDevice(idx, d)
	}
	return nil
}
func parseb(v string) int64 {
	if v == "" {
		return 0
	}
	rv, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		panic(err)
	}
	return rv
}

type SessionList []Session

func GenerateSessions(localip string) []Session {
	//scan through sessions
	//if, at N, there existed a same (same srcip:port dstip:port proto) session at N-1
	//   add the delta in bytes to the session rv
	//if it did not exist
	//   add all the bytes to the session rv
	//Then turn map into list, sorting by sum(rx+tx) and return

	rvm := make(map[sesskey]Session)
	_ = rvm
	lastiter := make(map[sesskey]Session)
	_ = lastiter
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	conns := session.DB("autowall").C("connections")
	iter := conns.Find(bson.M{"$or": []bson.M{bson.M{"srcaddress": localip}, bson.M{"srcaddressnoport": localip}}}).Sort("_sample").Iter()
	var result map[string]string
	thisiter := make(map[sesskey]Session)
	sample := ""
	for iter.Next(&result) {
		if result["protocol"] == "icmp" {
			continue
		}
		if result["protocol"] == "" {
			continue
		}
		if sample == "" {
			sample = result["_sample"]
		} else if sample != result["_sample"] {
			lastiter = thisiter
			thisiter = make(map[sesskey]Session)
			sample = result["_sample"]
		}
		//spew.Dump(result)
		dstaddrport := result["dstaddress"]
		srcaddrport := result["srcaddress"]
		proto := result["protocol"]
		skey := sesskey{srcaddrport, dstaddrport, proto}
		last, lastok := lastiter[skey]
		txbytes := parseb(result["origbytes"])
		rxbytes := parseb(result["replybytes"])
		txbytes_ := txbytes
		rxbytes_ := rxbytes
		if lastok {
			//fmt.Printf("found continuation of %#v\n", skey)
			lasttxbytes := last.TXBytes
			lastrxbytes := last.RXBytes
			txbytes -= lasttxbytes
			rxbytes -= lastrxbytes
		} else {
			//fmt.Printf("did not find continuation of %#v\n", skey)
		}
		ex, exok := rvm[skey]
		if !exok {
			ex = Session{
				ToAddr:   dstaddrport,
				Protocol: proto,
			}
		}
		ex.TXBytes += txbytes
		ex.RXBytes += rxbytes
		rvm[skey] = ex
		thisiter[skey] = Session{TXBytes: txbytes_, RXBytes: rxbytes_}
		//fmt.Printf("found %v\n", result)
	}
	//spew.Dump(rvm)
	iter.Close()
	//Now lets make sessions that are combined over src port
	crvm := make(map[sesskey]Session)
	for _, s := range rvm {
		skey := sesskey{Dstipport: s.ToAddr, Proto: s.Protocol}
		ex, exok := crvm[skey]
		if !exok {
			ex = Session{
				ToAddr:   s.ToAddr,
				Protocol: s.Protocol,
			}
		}
		ex.TXBytes += s.TXBytes
		ex.RXBytes += s.RXBytes
		crvm[skey] = ex
	}
	//Now lets turn into a list
	rvlist := []Session{}
	for _, s := range crvm {
		if s.ToAddr == "" {
			fmt.Printf("dropping session:")
			spew.Dump(s)
			continue
		}
		rvlist = append(rvlist, s)
	}
	//Now lets sort it
	sort.Sort(SessionList(rvlist))

	return rvlist
}

func (s SessionList) Len() int {
	return len(s)
}
func (s SessionList) Less(i, j int) bool {
	return (s[i].RXBytes + s[i].TXBytes) > (s[j].RXBytes + s[j].TXBytes)
}
func (s SessionList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type Interface interface {
	// Len is the number of elements in the collection.
	Len() int
	// Less reports whether the element with
	// index i should sort before the element with index j.
	Less(i, j int) bool
	// Swap swaps the elements with indexes i and j.
	Swap(i, j int)
}

func fmtdat(d int64) string {
	if d < 1024 {
		return fmt.Sprintf("%d B", d)
	}
	d /= 1024
	if d < 1024 {
		return fmt.Sprintf("%d KB", d)
	}
	d /= 1024
	if d < 1024 {
		return fmt.Sprintf("%d MB", d)
	}
	d /= 1024
	return fmt.Sprintf("%d GB", d)
}
func presentDevice(idx int, d Device) {
	//yellow := color.New(color.FgHiYellow).SprintFunc()
	fl := color.New(color.FgHiBlue).SprintFunc()
	//red := color.New(color.FgHiRed).SprintFunc()
	//blue := color.New(color.FgHiBlue).SprintFunc()
	color.Set(color.FgHiBlue)
	fmt.Printf("Device #%d\n", idx)
	color.Unset()
	fmt.Printf("%s %-9s\n", fl("Hostname:"), d.Hostname)
	fmt.Printf("%s %-12s %s %-6s %s %-8s\n",
		fl("IP:"), d.IP, fl("Link:"), d.Origin, fl("MAC:"), d.MAC)
	fmt.Printf("%s %-s\n", fl("NIC Mfg:"), d.Mfg)
	if len(d.Sessions) == 0 {
		fmt.Printf("%s\n", fl("No observed network activity"))
	} else {
		fmt.Printf("%s\n", fl("Dominant network activity:"))
		for _, s := range d.Sessions {
			fmt.Printf("=]%s %s/%s  %s %-4s %s %-4s\n",
				fl("To:"), s.Protocol, s.ToAddr, fl("TX:"), fmtdat(s.TXBytes), fl("RX:"), fmtdat(s.RXBytes))
			fmt.Printf("  %s %s\n", fl("Host:"), s.ToHost)
			if s.Whois == nil {
				fmt.Printf("  %s\n", fl("DST info unavailable"))
			} else {
				fmt.Printf("  %s %s %s %s\n", fl("DST Org:"), s.Whois.Org, fl("ISP:"), s.Whois.ISP)
				fmt.Printf("  %s %s\n", fl("DST AS:"), s.Whois.AS)
				fmt.Printf("  %s %s %s %s %s %s\n",
					fl("DST Country:"), s.Whois.Country, fl("Region:"), s.Whois.Region, fl("City:"), s.Whois.City)
			}
		}
	}
	fmt.Printf("\n\n")
}
