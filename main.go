package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/miekg/dns"
)

var (
	domainStore = make(map[string][]net.IP)
	mutex       sync.Mutex
	filters     filterFlag
)

type filterFlag []string

func (f *filterFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *filterFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	listDevices := flag.Bool("list", false, "List all available devices")
	deviceName := flag.String("device", "", "Device to sniff on")
	dnsPort := flag.Uint("dnsport", 5353, "DNS AXFR server port")
	flag.Var(&filters, "filter", "Filter stored domains (can be used multiple times)")

	flag.Parse()

	if len(filters) == 0 {
		filters = append(filters, "googlevideo.com")
	}

	if *listDevices {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("Error finding devices: %v", err)
		}

		fmt.Println("Available devices:")
		for _, dev := range devices {
			fmt.Printf("%s: %s\n", dev.Name, dev.Description)
		}
		return
	}

	if *deviceName == "" {
		var err error
		*deviceName, err = detectWANInterface()
		if err != nil {
			log.Fatalf("No device specified and failed to auto-detect WAN interface: %v", err)
		}
		log.Printf("Auto-detected WAN interface: %s", *deviceName)
	}

	// Open device
	handle, err := pcap.OpenLive(*deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", *deviceName, err)
	}
	defer handle.Close()

	// Set filter for DNS traffic
	var filter = "udp port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	fmt.Printf("Monitoring DNS traffic on device: %s...\n", *deviceName)

	// Start DNS server in a separate goroutine
	go startDNSServer(*dnsPort)

	// Create a channel to handle termination signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			domain := printDNSInfo(packet)
			if shouldFilterDomain(domain) {
				log.Println(domain)
				storeDomainNames(packet)
			}
		case <-stop:
			fmt.Println("Terminating...")
			return
		}
	}
}

func storeDomainNames(packet gopacket.Packet) {
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		mutex.Lock()
		for _, question := range dns.Questions {
			domainStore[string(question.Name)] = []net.IP{}
		}
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA {
				domain := string(answer.Name)
				ip := answer.IP
				domainStore[domain] = append(domainStore[domain], ip)
			}
		}
		mutex.Unlock()
	}
}

func printDNSInfo(packet gopacket.Packet) string {
	domain := ""
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		for _, question := range dns.Questions {
			fmt.Printf("Domain: %s\n", string(question.Name))
			domain = string(question.Name)
		}
		for _, answer := range dns.Answers {
			if answer.Type == layers.DNSTypeA {
				fmt.Printf("Domain: %s -> IP: %s\n", string(answer.Name), answer.IP)
				domain = string(answer.Name)
			}
		}
	}
	return domain
}

func startDNSServer(port uint) {
	dns.HandleFunc(".", handleAXFRRequest)
	server := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: "udp"}
	fmt.Println("Starting DNS server...")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server on port %d: %v", port, err)
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range r.Question {
			if q.Qtype == dns.TypeAXFR {
				handleAXFRRequest(w, r)
				return
			}
		}
	}
	w.WriteMsg(m)
}

func handleAXFRRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		log.Println("No questions in request")
		return
	}

	requestedDomain := normalizeDomain(req.Question[0].Name)
	log.Printf("Received AXFR request for domain: %s", requestedDomain)

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.Answer = make([]dns.RR, 0)

	log.Println("Acquiring lock for domainStore")
	mutex.Lock()
	for domain, ips := range domainStore {
		normalizedDomain := normalizeDomain(domain)
		if !strings.HasSuffix(normalizedDomain, requestedDomain) {
			log.Printf("Skipping domain: %s (does not match requested domain %s)", normalizedDomain, requestedDomain)
			continue
		}

		if !shouldFilterDomain(normalizedDomain) {
			log.Printf("Skipping domain: %s (filtered out)", normalizedDomain)
			continue
		}

		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s IN A %s", normalizedDomain, ip))
			if err != nil {
				log.Printf("Error creating DNS RR for domain %s: %v", normalizedDomain, err)
				continue
			}
			m.Answer = append(m.Answer, rr)
			log.Printf("Added RR: %s", rr.String())
		}
	}
	mutex.Unlock()
	log.Println("Released lock for domainStore")

	if len(m.Answer) == 0 {
		log.Println("No answers found, adding SOA record")
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2022010101,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  3600,
		})
	}

	log.Printf("Sending response with %d answers", len(m.Answer))
	if err := w.WriteMsg(m); err != nil {
		log.Printf("Error sending DNS response: %v", err)
	} else {
		log.Println("Response sent successfully")
	}
}

func shouldFilterDomain(domain string) bool {
	for _, filter := range filters {
		if strings.Contains(domain, filter) {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(domain, ".")
}

func detectWANInterface() (string, error) {
	routes, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error getting network interfaces: %v", err)
	}

	for _, iface := range routes {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			if ipNet.IP.To4() != nil {
				gw, err := getDefaultGateway()
				if err != nil {
					return "", err
				}
				if strings.Contains(gw.String(), ipNet.IP.String()) {
					return iface.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no default route found")
}

func getDefaultGateway() (net.IP, error) {
	routes, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("error getting interface addresses: %v", err)
	}

	for _, route := range routes {
		ipNet, ok := route.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ipNet.IP.To4() != nil {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("no default gateway found")
}
