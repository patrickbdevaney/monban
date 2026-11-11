// Go crypto/tls peer for q4-026: kx group SecP384r1MLKEM1024 (0x11ED) only, TLS 1.3 only.
//   gotls server <addr>   (self-signed ECDSA P-384, one request per connection, serves N=3 connections)
//   gotls client <addr>
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"time"
)

var groups = []tls.CurveID{tls.SecP384r1MLKEM1024}

func cert() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "monban.test"},
		DNSNames: []string{"monban.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func main() {
	fmt.Printf("go %s, crypto/tls, CurvePreferences=[SecP384r1MLKEM1024 0x%04x]\n", runtime.Version(), uint16(tls.SecP384r1MLKEM1024))
	switch os.Args[1] {
	case "server":
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: groups, Certificates: []tls.Certificate{cert()}}
		l, err := tls.Listen("tcp", os.Args[2], cfg)
		if err != nil {
			panic(err)
		}
		for i := 0; i < 3; i++ {
			c, err := l.Accept()
			if err != nil {
				panic(err)
			}
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				fmt.Println("handshake error:", err)
				c.Close()
				continue
			}
			st := tc.ConnectionState()
			line, _ := bufio.NewReader(tc).ReadString('\n')
			fmt.Printf("server handshake OK: group=%v (0x%04x) suite=%s; got %q\n", st.CurveID, uint16(st.CurveID), tls.CipherSuiteName(st.CipherSuite), line)
			io.WriteString(tc, "HTTP/1.0 200 OK\r\n\r\nhello from go crypto/tls 0x11ED\n")
			tc.Close()
		}
	case "client":
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: groups, InsecureSkipVerify: true, ServerName: "monban.test"}
		c, err := tls.Dial("tcp", os.Args[2], cfg)
		if err != nil {
			fmt.Println("client handshake error:", err)
			os.Exit(1)
		}
		st := c.ConnectionState()
		fmt.Printf("client handshake OK: group=%v (0x%04x) suite=%s\n", st.CurveID, uint16(st.CurveID), tls.CipherSuiteName(st.CipherSuite))
		io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
		b, _ := io.ReadAll(c)
		fmt.Printf("response: %q\n", string(b))
	}
}
