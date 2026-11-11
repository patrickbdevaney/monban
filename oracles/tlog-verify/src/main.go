package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tlog-verify verify --dir D --key VKEYFILE [--key VKEYFILE]...\n"+
		"       tlog-verify self-test --subject CMD --work DIR")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var dir, subject, work string
	var keys []string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			usage()
		}
		switch args[i] {
		case "--dir":
			dir = args[i+1]
		case "--key":
			keys = append(keys, args[i+1])
		case "--subject":
			subject = args[i+1]
		case "--work":
			work = args[i+1]
		default:
			usage()
		}
		i++
	}
	switch os.Args[1] {
	case "verify":
		r, err := verifyDir(dir, keys)
		if err != nil {
			fmt.Printf("TLOG-VERIFY: FAIL (%v)\n", err)
			os.Exit(1)
		}
		cos := "no ML-DSA-87 key configured"
		if r.cosigned {
			cos = "ML-DSA-87 cosignature line present on every checkpoint (signature not verified: no Go ML-DSA API)"
		}
		fmt.Printf("checked: %d entries (schema, gapless seq, leaf hash, inclusion), %d checkpoints (Ed25519 signed-note, "+
			"successive-pair consistency, tile roots); %s\n", r.entries, r.checkpoints, cos)
		fmt.Printf("TLOG-VERIFY: PASS (%d entries, %d checkpoints)\n", r.entries, r.checkpoints)
	case "self-test":
		if err := selfTest(subject, work); err != nil {
			fmt.Printf("TLOG-VERIFY SELF-TEST: FAIL (%v)\n", err)
			os.Exit(1)
		}
	default:
		usage()
	}
}

// ---- self-test ----

const (
	stOrigin = "selftest.example/log"
	stEdSeed = "1111111111111111111111111111111111111111111111111111111111111111"
	stPQSeed = "2222222222222222222222222222222222222222222222222222222222222222"
	stN      = 1000
)

func runSubject(subject, out string, extra ...string) error {
	f := strings.Fields(subject)
	if len(f) == 0 {
		return fmt.Errorf("empty subject")
	}
	args := append(f[1:], "--out", out, "--n", strconv.Itoa(stN), "--checkpoints", "300,600", "--origin", stOrigin,
		"--key-seed", stEdSeed, "--pq-seed", stPQSeed)
	args = append(args, extra...)
	cmd := exec.Command(f[0], args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

// readAllEntries returns the head tree's entries from a log directory (no verification).
func readAllEntries(dir string) ([][]byte, error) {
	msg, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(msg), "\n")
	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for b := int64(0); b*256 < n; b++ {
		e, err := readBundle(dir, b, int(min(n-b*256, 256)))
		if err != nil {
			return nil, err
		}
		out = append(out, e...)
	}
	return out, nil
}

func edSigner() (note.Signer, string, error) {
	seed, _ := hexDecode(stEdSeed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	vkey, err := note.NewEd25519VerifierKey(stOrigin, pub)
	if err != nil {
		return nil, "", err
	}
	h := sha256.New()
	h.Write([]byte(stOrigin + "\n\x01"))
	h.Write(pub)
	id := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	skey := "PRIVATE+KEY+" + stOrigin + "+" + hexKeyID(id) + "+" + base64.StdEncoding.EncodeToString(append([]byte{1}, seed...))
	s, err := note.NewSigner(skey)
	return s, vkey, err
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// writeLog is an independent tlog-tiles writer (x/mod tlog) used to build logs whose only defect is the one
// injected into the entries; it signs with the self-test Ed25519 seed. Returns the root and the vkey file path.
func writeLog(dir string, entries [][]byte) (tlog.Hash, string, error) {
	var stored []tlog.Hash
	hr := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			if x >= int64(len(stored)) {
				return nil, fmt.Errorf("hash %d not stored", x)
			}
			out[i] = stored[x]
		}
		return out, nil
	})
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hr)
		if err != nil {
			return tlog.Hash{}, "", err
		}
		stored = append(stored, hs...)
	}
	n := int64(len(entries))
	write := func(rel string, b []byte) error {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, b, 0o644)
	}
	for _, t := range tlog.NewTiles(tileH, 0, n) {
		data, err := tlog.ReadTileData(t, hr)
		if err != nil {
			return tlog.Hash{}, "", err
		}
		if err := write(tilePath(strconv.Itoa(t.L), t.N, t.W), data); err != nil {
			return tlog.Hash{}, "", err
		}
	}
	for b := int64(0); b*256 < n; b++ {
		var buf bytes.Buffer
		for _, e := range entries[b*256 : min(n, b*256+256)] {
			binary.Write(&buf, binary.BigEndian, uint16(len(e)))
			buf.Write(e)
		}
		if err := write(tilePath("entries", b, int(min(n-b*256, 256))), buf.Bytes()); err != nil {
			return tlog.Hash{}, "", err
		}
	}
	root, err := tlog.TreeHash(n, hr)
	if err != nil {
		return tlog.Hash{}, "", err
	}
	s, vkey, err := edSigner()
	if err != nil {
		return tlog.Hash{}, "", err
	}
	text := fmt.Sprintf("%s\n%d\n%s\n", stOrigin, n, base64.StdEncoding.EncodeToString(root[:]))
	msg, err := note.Sign(&note.Note{Text: text}, s)
	if err != nil {
		return tlog.Hash{}, "", err
	}
	if err := write("checkpoint", msg); err != nil {
		return tlog.Hash{}, "", err
	}
	kf := filepath.Join(dir, "..", filepath.Base(dir)+".vkey")
	return root, kf, os.WriteFile(kf, []byte(vkey+"\n"), 0o644)
}

func dropLine(path, prefixContains string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	removed := false
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if !removed && strings.HasPrefix(l, "— ") && prefixContains != "" && strings.Contains(l, prefixContains) {
			removed = true
			continue
		}
		out = append(out, l)
	}
	if !removed {
		return fmt.Errorf("no signature line matching %q", prefixContains)
	}
	return os.WriteFile(path, []byte(strings.Join(out, "")), 0o644)
}

func sigLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "— ") {
			out = append(out, l)
		}
	}
	return out, nil
}

type mutation struct {
	name string
	want []string
	// apply mutates dir (a fresh copy of the subject's log) and returns the trusted key files to use.
	apply func(dir string, keys []string) ([]string, error)
}

func selfTest(subject, work string) error {
	base := filepath.Join(work, "base")
	fork := filepath.Join(work, "fork")
	if err := runSubject(subject, base); err != nil {
		return fmt.Errorf("subject run: %v", err)
	}
	if err := runSubject(subject, fork, "--variant", "1"); err != nil {
		return fmt.Errorf("subject fork run: %v", err)
	}
	keys := []string{filepath.Join(work, "trusted.vkey"), filepath.Join(work, "trusted.vkey.mldsa87")}
	for i, f := range []string{"vkey", "vkey.mldsa87"} {
		b, err := os.ReadFile(filepath.Join(base, f))
		if err != nil {
			return err
		}
		if err := os.WriteFile(keys[i], b, 0o644); err != nil {
			return err
		}
	}
	// Control 1: the unmutated subject output passes.
	r, err := verifyDir(base, keys)
	if err != nil {
		return fmt.Errorf("control: unmutated subject log rejected: %v", err)
	}
	fmt.Printf("control: unmutated subject log passes (%d entries, %d checkpoints)\n", r.entries, r.checkpoints)
	baseEntries, err := readAllEntries(base)
	if err != nil {
		return err
	}
	// Control 2: an independent x/mod rebuild of the same entries gives the same root and passes, so the rebuilt
	// mutations below fail only for their injected defect.
	rb := filepath.Join(work, "rebuild")
	rroot, rkey, err := writeLog(rb, baseEntries)
	if err != nil {
		return err
	}
	head, err := openCheckpoint(filepath.Join(base, "checkpoint"), &trust{ed: mustVerifiers(keys[0]), name: stOrigin})
	if err != nil {
		return err
	}
	if rroot != head.tree.Hash {
		return fmt.Errorf("control: x/mod rebuild root %v != monban root %v", rroot, head.tree.Hash)
	}
	if _, err := verifyDir(rb, []string{rkey}); err != nil {
		return fmt.Errorf("control: x/mod rebuild rejected: %v", err)
	}
	fmt.Println("control: x/mod tlog rebuild of the same entries reproduces the monban root and passes")
	// Control 3: monban-bin's layout, both keys in one file (Ed25519 line, then ML-DSA-87 line), passes and is cosigned.
	kb := [2][]byte{}
	for i := range keys {
		if kb[i], err = os.ReadFile(keys[i]); err != nil {
			return err
		}
	}
	combined := filepath.Join(work, "trusted.vkey.combined")
	if err := os.WriteFile(combined, append(append([]byte(nil), kb[0]...), kb[1]...), 0o644); err != nil {
		return err
	}
	if r, err := verifyDir(base, []string{combined}); err != nil || !r.cosigned {
		return fmt.Errorf("control: combined vkey file (monban-bin layout) rejected or not cosigned: %v", err)
	}
	fmt.Println("control: combined vkey file (monban-bin layout) passes with the ML-DSA-87 cosignature checked")

	rebuilt := func(edit func([][]byte) [][]byte) func(string, []string) ([]string, error) {
		return func(dir string, _ []string) ([]string, error) {
			es := make([][]byte, len(baseEntries))
			for i, e := range baseEntries {
				es[i] = append([]byte(nil), e...)
			}
			if err := os.RemoveAll(dir); err != nil {
				return nil, err
			}
			_, k, err := writeLog(dir, edit(es))
			return []string{k}, err
		}
	}
	// reordered-entries: swap two entries of bundle 0, then re-serve the original (monban) tiles.
	reorder := func(d string, k []string) ([]string, error) {
		p := filepath.Join(d, "tile/entries/000")
		es, err := readBundle(d, 0, 256)
		if err != nil {
			return nil, err
		}
		es[3], es[4] = es[4], es[3]
		var buf bytes.Buffer
		for _, e := range es {
			binary.Write(&buf, binary.BigEndian, uint16(len(e)))
			buf.Write(e)
		}
		return k, os.WriteFile(p, buf.Bytes(), 0o644)
	}

	muts := []mutation{
		{"tampered-leaf-byte", []string{"leaf-hash"}, func(d string, k []string) ([]string, error) {
			p := filepath.Join(d, "tile/entries/001")
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			b[2+20] ^= 0x01
			return k, os.WriteFile(p, b, 0o644)
		}},
		{"reordered-entries", []string{"leaf-hash"}, reorder},
		{"swapped-tiles", []string{"tree"}, func(d string, k []string) ([]string, error) {
			a, b := filepath.Join(d, "tile/0/000"), filepath.Join(d, "tile/0/001")
			x, _ := os.ReadFile(a)
			y, _ := os.ReadFile(b)
			if err := os.WriteFile(a, y, 0o644); err != nil {
				return nil, err
			}
			return k, os.WriteFile(b, x, 0o644)
		}},
		{"forked-checkpoint-history", []string{"consistency", "tree"}, func(d string, k []string) ([]string, error) {
			b, err := os.ReadFile(filepath.Join(fork, "history/600"))
			if err != nil {
				return nil, err
			}
			return k, os.WriteFile(filepath.Join(d, "history/600"), b, 0o644)
		}},
		{"forked-checkpoint-same-size", []string{"fork"}, func(d string, k []string) ([]string, error) {
			b, err := os.ReadFile(filepath.Join(fork, "checkpoint"))
			if err != nil {
				return nil, err
			}
			return k, os.WriteFile(filepath.Join(d, "checkpoint"), b, 0o644)
		}},
		{"forked-head-and-history", []string{"tree"}, func(d string, k []string) ([]string, error) {
			b, err := os.ReadFile(filepath.Join(fork, "checkpoint"))
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(d, "checkpoint"), b, 0o644); err != nil {
				return nil, err
			}
			return k, os.WriteFile(filepath.Join(d, "history", strconv.Itoa(stN)), b, 0o644)
		}},
		{"rollback-head", []string{"fork"}, func(d string, k []string) ([]string, error) {
			b, err := os.ReadFile(filepath.Join(d, "history/600"))
			if err != nil {
				return nil, err
			}
			return k, os.WriteFile(filepath.Join(d, "checkpoint"), b, 0o644)
		}},
		{"missing-log-signature", []string{"signature"}, func(d string, k []string) ([]string, error) {
			ls, err := sigLines(filepath.Join(d, "checkpoint"))
			if err != nil || len(ls) == 0 {
				return nil, fmt.Errorf("no signature lines")
			}
			return k, dropLine(filepath.Join(d, "checkpoint"), ls[0])
		}},
		{"unsigned-checkpoint", []string{"signature"}, func(d string, k []string) ([]string, error) {
			b, err := os.ReadFile(filepath.Join(d, "checkpoint"))
			if err != nil {
				return nil, err
			}
			i := bytes.LastIndex(b, []byte("\n\n"))
			return k, os.WriteFile(filepath.Join(d, "checkpoint"), b[:i+1], 0o644)
		}},
		{"missing-mldsa87-cosignature", []string{"cosignature"}, func(d string, k []string) ([]string, error) {
			ls, err := sigLines(filepath.Join(d, "checkpoint"))
			if err != nil || len(ls) < 2 {
				return nil, fmt.Errorf("want 2 signature lines")
			}
			return k, dropLine(filepath.Join(d, "checkpoint"), ls[1])
		}},
		{"combined-vkey-bad-line", []string{"keys"}, func(d string, k []string) ([]string, error) {
			p := filepath.Join(d, "..", "bad-combined.vkey")
			return []string{p}, os.WriteFile(p, append(append([]byte(nil), kb[0]...), []byte("monban.audit+00000000+AAAA\n")...), 0o644)
		}},
		{"combined-vkey-no-mldsa", []string{"cosignature"}, func(d string, k []string) ([]string, error) {
			// a combined file whose second line is a valid but foreign ML-DSA-87 key: the log's cosignature is not
			// by that key, so the checkpoint lacks a matching cosignature line
			mat, err := base64.StdEncoding.DecodeString(strings.SplitN(strings.TrimSpace(string(kb[1])), "+", 3)[2])
			if err != nil {
				return nil, err
			}
			mat[len(mat)-1] ^= 0x01
			h := sha256.New()
			h.Write([]byte(stOrigin + "\n"))
			h.Write(mat)
			line := fmt.Sprintf("%s+%08x+%s\n", stOrigin, binary.BigEndian.Uint32(h.Sum(nil)[:4]), base64.StdEncoding.EncodeToString(mat))
			p := filepath.Join(d, "..", "foreign-combined.vkey")
			return []string{p}, os.WriteFile(p, append(append([]byte(nil), kb[0]...), []byte(line)...), 0o644)
		}},
		{"untrusted-key", []string{"signature"}, func(d string, k []string) ([]string, error) {
			_, vk, err := note.GenerateKey(rand.Reader, stOrigin)
			if err != nil {
				return nil, err
			}
			p := filepath.Join(d, "..", "other.vkey")
			return []string{p}, os.WriteFile(p, []byte(vk+"\n"), 0o644)
		}},
		{"seq-gap", []string{"seq"}, rebuilt(func(es [][]byte) [][]byte {
			for i := 500; i < len(es); i++ {
				es[i] = bytes.Replace(es[i], []byte(fmt.Sprintf(`"seq":%d,`, i)), []byte(fmt.Sprintf(`"seq":%d,`, i+1)), 1)
			}
			return es
		})},
		{"schema-extra-field", []string{"schema"}, rebuilt(func(es [][]byte) [][]byte {
			es[42] = bytes.Replace(es[42], []byte(`{"v":1,`), []byte(`{"v":1,"forged":true,`), 1)
			return es
		})},
		{"schema-duplicate-key", []string{"schema"}, rebuilt(func(es [][]byte) [][]byte {
			es[43] = bytes.Replace(es[43], []byte(`{"v":1,`), []byte(`{"v":1,"v":1,`), 1)
			return es
		})},
		{"unescaped-attacker-byte", []string{"schema"}, rebuilt(func(es [][]byte) [][]byte {
			es[44] = bytes.Replace(es[44], []byte(`"object":"`), []byte("\"object\":\"\x1b[31m"), 1)
			return es
		})},
		{"truncated-bundle", []string{"entries"}, func(d string, k []string) ([]string, error) {
			w := stN % 256
			p := filepath.Join(d, tilePath("entries", stN/256, w))
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			off := 0
			for i := 0; i < w-1; i++ {
				off += 2 + int(binary.BigEndian.Uint16(b[off:]))
			}
			return k, os.WriteFile(p, b[:off], 0o644)
		}},
		{"missing-partial-tile", []string{"tree", "tiles"}, func(d string, k []string) ([]string, error) {
			return k, os.Remove(filepath.Join(d, tilePath("0", stN/256, stN%256)))
		}},
	}
	caught := 0
	for i, m := range muts {
		d := filepath.Join(work, fmt.Sprintf("m%02d", i))
		if err := copyDir(base, d); err != nil {
			return err
		}
		ks, err := m.apply(d, keys)
		if err != nil {
			return fmt.Errorf("mutation %s: apply: %v", m.name, err)
		}
		_, verr := verifyDir(d, ks)
		if verr == nil {
			return fmt.Errorf("mutation %s NOT caught (verifier passed)", m.name)
		}
		cat := category(verr)
		ok := false
		for _, w := range m.want {
			ok = ok || cat == w
		}
		if !ok {
			return fmt.Errorf("mutation %s failed for the wrong reason: %v (want %v)", m.name, verr, m.want)
		}
		fmt.Printf("mutation %-28s caught: %v\n", m.name, verr)
		caught++
		os.RemoveAll(d)
	}
	fmt.Printf("TLOG-VERIFY SELF-TEST: PASS (%d/%d mutations caught for the intended reason; 3 controls pass)\n", caught, len(muts))
	return nil
}

func mustVerifiers(path string) []note.Verifier {
	t, err := loadTrust([]string{path})
	if err != nil {
		return nil
	}
	return t.ed
}
