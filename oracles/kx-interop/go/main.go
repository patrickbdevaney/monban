// kx-interop Go peer: Go crypto/tls (stdlib only) as an independent TLS 1.3 implementation of
// 0x11ED SecP384r1MLKEM1024, 0x11EB SecP256r1MLKEM768, 0x11EC X25519MLKEM768 and 0x0202 MLKEM1024.
//
//	gopeer probe
//	    in-memory Go<->Go handshake per CurveID; prints "group 0x11ed ok" or "group 0x11ed fail <err>"
//	gopeer server -listen 127.0.0.1:0 -groups 0x11ed[,...] -cert leaf.pem -key leaf.key
//	    prints "LISTEN <port>", accepts ONE connection, prints "HANDSHAKE ok group=0x11ed hrr=false version=0x0304
//	    suite=0x1302" (or "HANDSHAKE fail err=..."), then echoes every application byte until EOF and prints
//	    "ECHOED <n>"
//	gopeer client -connect 127.0.0.1:PORT -groups 0x11ec,0x11ed -nonce NONCE
//	    prints "HANDSHAKE ok ..." / "HANDSHAKE fail ...", sends "NONCE\n", reads one line, prints "ECHO ok" or
//	    "ECHO mismatch ...", closes (close_notify). Exit 0 only when the handshake completed and the echo matched.
//
// The client does not verify the server certificate chain (the subject's credential is self-signed and generated
// at start-up); CertificateVerify and Finished are still verified by crypto/tls, so a key-schedule mismatch fails.
// Go sends a key share only for the first group of its fixed order (crypto/tls defaults.go curvePreferenceOrder:
// 0x11ec, 0x11eb, 0x11ed, 0x0202, x25519, P-256, P-384, P-521); -groups selects which of those are enabled.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var candidates = []tls.CurveID{
	tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.MLKEM1024,
	tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
}

func parseGroups(s string) ([]tls.CurveID, error) {
	var out []tls.CurveID
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(f), "0x"), 16, 16)
		if err != nil {
			return nil, fmt.Errorf("bad group %q", f)
		}
		out = append(out, tls.CurveID(v))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no groups")
	}
	return out, nil
}

func selfCert() (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aegis.test"},
		DNSNames: []string{"aegis.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func report(st tls.ConnectionState) string {
	return fmt.Sprintf("HANDSHAKE ok group=0x%04x hrr=%t version=0x%04x suite=0x%04x", uint16(st.CurveID),
		st.HelloRetryRequest, st.Version, st.CipherSuite)
}

func probe() int {
	cert, err := selfCert()
	if err != nil {
		fmt.Println("probe: cert:", err)
		return 1
	}
	for _, g := range candidates {
		a, b := net.Pipe()
		scfg := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{g}, Certificates: []tls.Certificate{cert}}
		ccfg := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{g}, InsecureSkipVerify: true}
		errc := make(chan error, 1)
		go func() { s := tls.Server(a, scfg); errc <- s.Handshake(); s.Close() }()
		c := tls.Client(b, ccfg)
		cerr := c.Handshake()
		got := c.ConnectionState().CurveID
		c.Close()
		serr := <-errc
		if cerr == nil && serr == nil && got == g {
			fmt.Printf("group 0x%04x ok\n", uint16(g))
		} else {
			fmt.Printf("group 0x%04x fail client=%v server=%v\n", uint16(g), cerr, serr)
		}
	}
	return 0
}

func server(args []string) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:0", "listen address")
	groups := fs.String("groups", "", "comma list of hex CurveIDs")
	certf := fs.String("cert", "", "PEM certificate chain")
	keyf := fs.String("key", "", "PEM private key")
	if fs.Parse(args) != nil {
		return 2
	}
	gs, err := parseGroups(*groups)
	if err != nil {
		fmt.Println("server:", err)
		return 2
	}
	cert, err := tls.LoadX509KeyPair(*certf, *keyf)
	if err != nil {
		fmt.Println("server: credential:", err)
		return 2
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: gs,
		Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Println("server: listen:", err)
		return 1
	}
	fmt.Printf("LISTEN %d\n", l.Addr().(*net.TCPAddr).Port)
	c, err := l.Accept()
	l.Close()
	if err != nil {
		fmt.Println("server: accept:", err)
		return 1
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	tc := tls.Server(c, cfg)
	if err := tc.Handshake(); err != nil {
		fmt.Printf("HANDSHAKE fail err=%q\n", err.Error())
		c.Close()
		return 1
	}
	fmt.Println(report(tc.ConnectionState()))
	n, err := io.Copy(tc, tc)
	fmt.Printf("ECHOED %d\n", n)
	if err != nil {
		fmt.Printf("ECHO error err=%q\n", err.Error())
	}
	tc.Close()
	return 0
}

func client(args []string) int {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	connect := fs.String("connect", "", "host:port")
	groups := fs.String("groups", "", "comma list of hex CurveIDs")
	nonce := fs.String("nonce", "", "application data line to send and expect back")
	if fs.Parse(args) != nil || *nonce == "" {
		return 2
	}
	gs, err := parseGroups(*groups)
	if err != nil {
		fmt.Println("client:", err)
		return 2
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: gs,
		InsecureSkipVerify: true, ServerName: "aegis.test", ClientSessionCache: nil}
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.Dial("tcp", *connect)
	if err != nil {
		fmt.Println("client: dial:", err)
		return 1
	}
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		fmt.Printf("HANDSHAKE fail err=%q\n", err.Error())
		raw.Close()
		return 1
	}
	fmt.Println(report(c.ConnectionState()))
	if _, err := io.WriteString(c, *nonce+"\n"); err != nil {
		fmt.Printf("ECHO write-error err=%q\n", err.Error())
		c.Close()
		return 1
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if err != nil || strings.TrimRight(line, "\r\n") != *nonce {
		fmt.Printf("ECHO mismatch got=%q err=%v\n", line, err)
		return 1
	}
	fmt.Println("ECHO ok")
	return 0
}

func main() {
	fmt.Printf("gopeer %s crypto/tls\n", runtime.Version())
	if len(os.Args) < 2 {
		fmt.Println("usage: gopeer probe | server ... | client ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "probe":
		os.Exit(probe())
	case "server":
		os.Exit(server(os.Args[2:]))
	case "client":
		os.Exit(client(os.Args[2:]))
	default:
		fmt.Println("unknown mode", os.Args[1])
		os.Exit(2)
	}
}
