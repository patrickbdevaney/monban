// lcx-gopeer: Go crypto/tls (stdlib only) TLS 1.3 client for the P7-libcrux-001 interop matrix.
//
//	lcx-gopeer -connect 127.0.0.1:PORT -group 0x11ec -ca ca.pem -nonce NONCE
//
// Verifies the server chain against -ca for server name aegis.test (so the server's CertificateVerify signature,
// made by the libcrux provider, is checked by an independent implementation), enables only -group, prints
// "HANDSHAKE ok group=0x.... suite=0x.... sig=<leaf key type>" or "HANDSHAKE fail err=...", sends "NONCE\n",
// reads one line back and prints "ECHO ok" or "ECHO mismatch". Exit 0 only when both succeeded.
// Go does not let a client restrict TLS 1.3 cipher suites; the server side pins the suite per cell.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() { os.Exit(run()) }

func run() int {
	connect := flag.String("connect", "", "host:port")
	group := flag.String("group", "", "hex CurveID")
	caf := flag.String("ca", "", "PEM CA file")
	nonce := flag.String("nonce", "", "nonce to echo")
	flag.Parse()
	g, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(*group), "0x"), 16, 16)
	if err != nil {
		fmt.Println("usage: bad -group")
		return 2
	}
	pem, err := os.ReadFile(*caf)
	if err != nil {
		fmt.Println("usage: -ca:", err)
		return 2
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fmt.Println("usage: -ca has no certificates")
		return 2
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: "aegis.test",
		RootCAs: roots, CurvePreferences: []tls.CurveID{tls.CurveID(g)}}
	d := &tls.Dialer{Config: cfg}
	c, err := d.Dial("tcp", *connect)
	if err != nil {
		fmt.Printf("HANDSHAKE fail err=%q\n", err.Error())
		return 1
	}
	defer c.Close()
	tc := c.(*tls.Conn)
	_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
	st := tc.ConnectionState()
	sig := "unknown"
	if len(st.PeerCertificates) > 0 {
		sig = st.PeerCertificates[0].PublicKeyAlgorithm.String()
	}
	fmt.Printf("HANDSHAKE ok group=0x%04x suite=0x%04x sig=%s version=0x%04x\n", uint16(st.CurveID), st.CipherSuite,
		sig, st.Version)
	if _, err := tc.Write([]byte(*nonce + "\n")); err != nil {
		fmt.Printf("ECHO fail err=%q\n", err.Error())
		return 1
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil || strings.TrimRight(line, "\n") != *nonce {
		fmt.Printf("ECHO mismatch got=%q err=%v\n", line, err)
		return 1
	}
	fmt.Println("ECHO ok")
	_ = tc.CloseWrite()
	return 0
}
