// Command mockdns is a tiny classic DNS (UDP) server used by the end-to-end
// smoke test. It answers A queries for known names and NXDOMAIN otherwise.
package main

import (
	"context"
	"log"
	"os"

	"github.com/miekg/dns"
)

func main() {
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8053"
	}
	mux := &dns.ServeMux{}
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) > 0 {
			name := req.Question[0].Name
			switch name {
			case "allowed.test.":
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   []byte{1, 2, 3, 4},
				}}
			case "ads.example.com.":
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   []byte{9, 9, 9, 9},
				}}
			default:
				resp.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(resp)
	})
	srv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	log.Println("mockdns on", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
	<-context.Background().Done()
}
