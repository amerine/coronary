package main

import (
	"fmt"
	"time"
	"net"
	"os"
	"log"
	"flag"

	"github.com/titanous/heartbleeder/tls"
)

var defaultTLSConfig = tls.Config{InsecureSkipVerify: true}

type Host struct {
	address    string
	state      string
	message    string
}

func main() {
	numScanners := flag.Int("s", 99, "how many async checks you might want.")
	printErrors := flag.Bool("error", false, "prints connection errors (timeouts, etc)")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] host\n", os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
	}
	flag.Parse()
	cidr := flag.Arg(0)
	pending, complete := make(chan *Host), make(chan *Host)

	go func() {
		fmt.Printf("Scanning: %s\n", cidr)
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatal(err)
		}

		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			host := fmt.Sprintf("%s:443", ip)
			pending <- &Host{address: host}
		}
	}()

	for i := 0; i < *numScanners; i++ {
		go scanner(pending, complete)
	}

	for {
		select {
		case host := <-complete:
			if *printErrors || host.state != "ERROR" {
				fmt.Printf("%s - %s", host.state, host.message)
			}
		case <-time.After(300 * time.Second):
			fmt.Println("No updates in 300 seconds. Exiting")
			os.Exit(0)
		}
	}
}

func inc(ip net.IP) {
	for j := len(ip)-1; j>=0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanner(in <-chan *Host, out chan<- *Host) {
	for {
		select {
		case host := <-in:
			host.check()
			out <- host
		}
	}
}

func (h *Host) check() {
	var c *tls.Conn
	var err error

	dialer := &net.Dialer{Timeout: 5*time.Second}
	c, err = tls.DialWithDialer(dialer, "tcp", h.address, &defaultTLSConfig)

	if err != nil {
		h.state = "ERROR"
		h.message = fmt.Sprintf("Error connecting to host: %s\n", err)
		return
	}

	err = c.WriteHeartbeat(1, nil)
	if err == tls.ErrNoHeartbeat {
		h.state = "SECURE"
		h.message = fmt.Sprintf("%s does not have the heartbeat extension enabled\n", h.address)
		return
	}

	if err != nil {
		h.state = "UNKNOWN"
		h.message = fmt.Sprintf("Heartbeat enabled, but there was an error writing the payload:", err)
		return
	}

	readErr := make(chan error)
	go func() {
		_, _, err := c.ReadHeartbeat()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			h.state = "VULNERABLE"
			h.message = fmt.Sprintf("%s has the heartbeat extension enabled and is vulnerable to CVE-2014-0160\n", h.address)
			return
		}

		h.state = "SECURE"
		h.message = fmt.Sprintf("%s has heartbeat extension enabled but is not vulnerable\n", h.address)
		return
	case <-time.After(5 * time.Second):
		h.state = "SECURE"
		h.message = fmt.Sprintf("%s has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)\n", h.address)
		return
	}
}
