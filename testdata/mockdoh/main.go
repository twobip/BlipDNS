// Command mockdoh is a tiny RFC 8484 DoH server used by the end-to-end
// smoke test. It answers A queries for known names and NXDOMAIN otherwise.
package main

import (
	"io"
	"log"
	"net/http"
	"os"

	"github.com/miekg/dns"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var buf []byte
		var err error
		if r.Method == http.MethodGet {
			buf, err = base64urlDecode(r.URL.Query().Get("dns"))
		} else {
			buf, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		}
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(buf); err != nil {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		if len(q.Question) > 0 {
			name := q.Question[0].Name
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
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	})
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8053"
	}
	log.Println("mockdoh on", addr)
	log.Fatal(http.ListenAndServeTLS(addr, os.Getenv("MOCK_CERT"), os.Getenv("MOCK_KEY"), mux))
}

func base64urlDecode(s string) ([]byte, error) {
	if len(s)%4 != 0 {
		s += string("===="[:4-len(s)%4])
	}
	return stdb64(s)
}
