// Independent verifier for a C2SP tlog-tiles audit log written by aegis-audit.
//
// Uses golang.org/x/mod/sumdb/note (signed-note open/verify) and golang.org/x/mod/sumdb/tlog (RFC 6962 tile
// authentication, tree hashes, record and tree proofs). Checkpoint text, tile paths, entry bundles and the F9 leaf
// schema are parsed here from the specs, not from aegis code.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const tileH = 8

// mldsaSigType is aegis' signed-note type for ML-DSA-87 cosignatures: 0xff followed by a longer identifier
// (c2sp.org/signed-note@v1.1.0 "Signature types").
var mldsaSigType = append([]byte{0xff}, []byte("aegis-mldsa87-note-v1")...)

const (
	mldsaPKLen  = 2592
	mldsaSigLen = 4627
)

// vErr carries a category so the self-test can check each mutation fails for the intended reason.
type vErr struct {
	cat string
	msg string
}

func (e *vErr) Error() string { return e.cat + ": " + e.msg }

func fail(cat, format string, a ...any) error { return &vErr{cat, fmt.Sprintf(format, a...)} }

func category(err error) string {
	var v *vErr
	if errors.As(err, &v) {
		return v.cat
	}
	return "other"
}

// ---- trusted keys ----

type pqKey struct {
	name string
	hash uint32
}

type trust struct {
	ed   []note.Verifier
	pq   []pqKey
	name string // log key name (= origin)
}

func loadTrust(files []string) (*trust, error) {
	t := &trust{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fail("keys", "%v", err)
		}
		vk := strings.TrimSpace(string(b))
		if v, err := note.NewVerifier(vk); err == nil {
			t.ed = append(t.ed, v)
			t.name = v.Name()
			continue
		}
		parts := strings.SplitN(vk, "+", 3)
		if len(parts) != 3 {
			return nil, fail("keys", "bad vkey in %s", f)
		}
		material, err := base64.StdEncoding.Strict().DecodeString(parts[2])
		if err != nil || !bytes.HasPrefix(material, mldsaSigType) || len(material) != len(mldsaSigType)+mldsaPKLen {
			return nil, fail("keys", "unsupported vkey in %s", f)
		}
		h := sha256.New()
		h.Write([]byte(parts[0] + "\n"))
		h.Write(material)
		id := binary.BigEndian.Uint32(h.Sum(nil)[:4])
		if fmt.Sprintf("%08x", id) != parts[1] {
			return nil, fail("keys", "ML-DSA-87 vkey key ID mismatch in %s", f)
		}
		t.pq = append(t.pq, pqKey{parts[0], id})
	}
	if len(t.ed) == 0 {
		return nil, fail("keys", "no Ed25519 log key")
	}
	return t, nil
}

// ---- checkpoints (c2sp.org/tlog-checkpoint@v1.1.0) ----

type checkpoint struct {
	origin string
	tree   tlog.Tree
	file   string
}

func openCheckpoint(path string, t *trust) (*checkpoint, error) {
	msg, err := os.ReadFile(path)
	if err != nil {
		return nil, fail("checkpoint", "%v", err)
	}
	n, err := note.Open(msg, note.VerifierList(t.ed...))
	if err != nil {
		return nil, fail("signature", "%s: %v", filepath.Base(path), err)
	}
	for _, k := range t.pq {
		found := false
		for _, s := range n.UnverifiedSigs {
			if s.Name == k.name && s.Hash == k.hash {
				raw, err := base64.StdEncoding.Strict().DecodeString(s.Base64)
				if err != nil || len(raw) != 4+mldsaSigLen {
					return nil, fail("cosignature", "%s: malformed ML-DSA-87 cosignature", filepath.Base(path))
				}
				found = true
			}
		}
		if !found {
			return nil, fail("cosignature", "%s: ML-DSA-87 cosignature line missing", filepath.Base(path))
		}
	}
	lines := strings.Split(n.Text, "\n")
	if len(lines) != 4 || lines[3] != "" {
		return nil, fail("checkpoint", "%s: want exactly origin/size/root lines", filepath.Base(path))
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != lines[1] {
		return nil, fail("checkpoint", "%s: bad tree size %q", filepath.Base(path), lines[1])
	}
	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(root) != tlog.HashSize || base64.StdEncoding.EncodeToString(root) != lines[2] {
		return nil, fail("checkpoint", "%s: bad root hash", filepath.Base(path))
	}
	if lines[0] == "" || lines[0] != t.name {
		return nil, fail("checkpoint", "%s: origin %q != log key name %q", filepath.Base(path), lines[0], t.name)
	}
	var h tlog.Hash
	copy(h[:], root)
	return &checkpoint{origin: lines[0], tree: tlog.Tree{N: size, Hash: h}, file: path}, nil
}

// ---- tiles (c2sp.org/tlog-tiles) ----

func encodeIndex(n int64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/", n%1000) + s
	}
	return s
}

func tilePath(level string, n int64, w int) string {
	p := "tile/" + level + "/" + encodeIndex(n)
	if w < 1<<tileH {
		p += fmt.Sprintf(".p/%d", w)
	}
	return p
}

type dirTiles struct {
	dir   string
	cache map[tlog.Tile][]byte
}

func (d *dirTiles) Height() int { return tileH }

func (d *dirTiles) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		if b, ok := d.cache[t]; ok {
			out[i] = b
			continue
		}
		if t.H != tileH || t.L < 0 {
			return nil, fail("tiles", "unexpected tile request %+v", t)
		}
		p := tilePath(strconv.Itoa(t.L), t.N, t.W)
		b, err := os.ReadFile(filepath.Join(d.dir, p))
		if err != nil {
			return nil, fail("tiles", "%s: %v", p, err)
		}
		if len(b) != t.W*tlog.HashSize {
			return nil, fail("tiles", "%s: %d bytes, want %d", p, len(b), t.W*tlog.HashSize)
		}
		d.cache[t] = b
		out[i] = b
	}
	return out, nil
}

func (d *dirTiles) SaveTiles([]tlog.Tile, [][]byte) {}

func readBundle(dir string, n int64, w int) ([][]byte, error) {
	p := tilePath("entries", n, w)
	b, err := os.ReadFile(filepath.Join(dir, p))
	if err != nil {
		return nil, fail("entries", "%s: %v", p, err)
	}
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fail("entries", "%s: truncated length prefix", p)
		}
		l := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+l {
			return nil, fail("entries", "%s: truncated entry", p)
		}
		out = append(out, b[2:2+l])
		b = b[2+l:]
	}
	if len(out) != w {
		return nil, fail("entries", "%s: %d entries, want %d", p, len(out), w)
	}
	return out, nil
}

// ---- F9 leaf schema (interfaces/F9-audit-event.schema.json) ----

// parseStrict decodes one JSON value, rejecting duplicate object keys and trailing data.
func parseStrict(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := walk(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

func walk(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("non-string key")
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				v, err := walk(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err := dec.Token()
			return m, err
		case '[':
			var a []any
			for dec.More() {
				v, err := walk(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
		return nil, errors.New("unexpected delimiter")
	default:
		return tok, nil
	}
}

var (
	reAction = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	reHex32  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reInt    = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !reInt.MatchString(string(n)) {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

func asStr(v any) (string, bool) { s, ok := v.(string); return s, ok }

func oneOf(v any, set ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// checkLeaf validates one leaf against F9 and returns its seq.
func checkLeaf(leaf []byte) (int64, error) {
	for _, c := range leaf {
		if c < 0x20 || c > 0x7e {
			return 0, fmt.Errorf("unescaped byte 0x%02x (leaves must be printable ASCII)", c)
		}
	}
	v, err := parseStrict(leaf)
	if err != nil {
		return 0, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return 0, errors.New("not an object")
	}
	allowed := map[string]bool{"v": true, "ts": true, "seq": true, "actor": true, "action": true, "object": true,
		"outcome": true, "req_id": true, "config_hash": true, "fips_status": true, "detail": true}
	for k := range m {
		if !allowed[k] {
			return 0, fmt.Errorf("unknown property %q", k)
		}
	}
	for _, k := range []string{"v", "ts", "seq", "actor", "action", "object", "outcome", "req_id", "config_hash", "fips_status"} {
		if _, ok := m[k]; !ok {
			return 0, fmt.Errorf("missing %q", k)
		}
	}
	if n, ok := asInt(m["v"]); !ok || n != 1 {
		return 0, errors.New("v != 1")
	}
	if s, ok := asStr(m["ts"]); !ok {
		return 0, errors.New("ts not a string")
	} else if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
		return 0, fmt.Errorf("ts not RFC 3339: %v", err)
	}
	seq, ok := asInt(m["seq"])
	if !ok || seq < 0 {
		return 0, errors.New("seq not a non-negative integer")
	}
	actor, ok := m["actor"].(map[string]any)
	if !ok {
		return 0, errors.New("actor not an object")
	}
	for k, av := range actor {
		switch k {
		case "kind":
			if !oneOf(av, "public", "principal", "admin", "system") {
				return 0, errors.New("bad actor.kind")
			}
		case "tenant":
			if n, ok := asInt(av); !ok || n < 1 {
				return 0, errors.New("bad actor.tenant")
			}
		case "subject_hash":
			if s, ok := asStr(av); !ok || !reHex64.MatchString(s) {
				return 0, errors.New("bad actor.subject_hash")
			}
		default:
			return 0, fmt.Errorf("unknown actor property %q", k)
		}
	}
	if _, ok := actor["kind"]; !ok {
		return 0, errors.New("actor.kind missing")
	}
	if s, ok := asStr(m["action"]); !ok || !reAction.MatchString(s) {
		return 0, errors.New("bad action")
	}
	if s, ok := asStr(m["object"]); !ok || utf8.RuneCountInString(s) > 512 {
		return 0, errors.New("bad object (not a string or > 512 chars)")
	}
	if !oneOf(m["outcome"], "allow", "deny", "error", "applied", "rolled_back") {
		return 0, errors.New("bad outcome")
	}
	if s, ok := asStr(m["req_id"]); !ok || !reHex32.MatchString(s) {
		return 0, errors.New("bad req_id")
	}
	if s, ok := asStr(m["config_hash"]); !ok || !reHex64.MatchString(s) {
		return 0, errors.New("bad config_hash")
	}
	if !oneOf(m["fips_status"], "none", "floor", "cmvp") {
		return 0, errors.New("bad fips_status")
	}
	if d, present := m["detail"]; present {
		dm, ok := d.(map[string]any)
		if !ok || len(dm) > 16 {
			return 0, errors.New("bad detail (not an object or > 16 properties)")
		}
		for k, dv := range dm {
			switch x := dv.(type) {
			case string, bool:
			case json.Number:
				if _, ok := asInt(x); !ok {
					return 0, fmt.Errorf("detail.%s not an integer", k)
				}
			default:
				return 0, fmt.Errorf("detail.%s has a disallowed type", k)
			}
		}
	}
	return seq, nil
}

// ---- the verification ----

type report struct {
	entries     int64
	checkpoints int
	cosigned    bool
}

func verifyDir(dir string, keyFiles []string) (*report, error) {
	t, err := loadTrust(keyFiles)
	if err != nil {
		return nil, err
	}
	head, err := openCheckpoint(filepath.Join(dir, "checkpoint"), t)
	if err != nil {
		return nil, err
	}
	// Checkpoint history (every published checkpoint), plus the head.
	cps := []*checkpoint{head}
	hist, _ := filepath.Glob(filepath.Join(dir, "history", "*"))
	for _, h := range hist {
		c, err := openCheckpoint(h, t)
		if err != nil {
			return nil, err
		}
		if filepath.Base(h) != strconv.FormatInt(c.tree.N, 10) {
			return nil, fail("checkpoint", "%s holds size %d", h, c.tree.N)
		}
		cps = append(cps, c)
	}
	sort.SliceStable(cps, func(i, j int) bool { return cps[i].tree.N < cps[j].tree.N })
	bySize := map[int64]tlog.Hash{}
	for _, c := range cps {
		if h, ok := bySize[c.tree.N]; ok && h != c.tree.Hash {
			return nil, fail("fork", "two signed checkpoints of size %d with different roots", c.tree.N)
		}
		bySize[c.tree.N] = c.tree.Hash
	}
	if last := cps[len(cps)-1]; last.tree.N != head.tree.N {
		return nil, fail("fork", "history has size %d beyond the head %d (rollback)", last.tree.N, head.tree.N)
	}

	tr := &dirTiles{dir: dir, cache: map[tlog.Tile][]byte{}}
	N := head.tree.N
	hr := tlog.TileHashReader(head.tree, tr)

	// 1. Tiles rebuild the signed root.
	th, err := tlog.TreeHash(N, hr)
	if err != nil {
		return nil, fail("tree", "head tiles do not authenticate: %v", err)
	}
	if th != head.tree.Hash {
		return nil, fail("tree", "tile root %v != checkpoint root %v", th, head.tree.Hash)
	}

	// 2. Every entry: bundle framing, leaf hash == authenticated level-0 tile hash, inclusion proof, F9 schema,
	// gapless seq.
	for n := int64(0); n*256 < N; n++ {
		w := int(min(N-n*256, 256))
		entries, err := readBundle(dir, n, w)
		if err != nil {
			return nil, err
		}
		idx := make([]int64, w)
		for k := range idx {
			idx[k] = tlog.StoredHashIndex(0, n*256+int64(k))
		}
		hashes, err := hr.ReadHashes(idx)
		if err != nil {
			return nil, fail("tree", "level-0 hashes for bundle %d: %v", n, err)
		}
		for k, e := range entries {
			i := n*256 + int64(k)
			rh := tlog.RecordHash(e)
			if rh != hashes[k] {
				return nil, fail("leaf-hash", "entry %d does not hash to its tile hash", i)
			}
			p, err := tlog.ProveRecord(N, i, hr)
			if err != nil {
				return nil, fail("inclusion", "entry %d: %v", i, err)
			}
			if err := tlog.CheckRecord(p, N, head.tree.Hash, i, rh); err != nil {
				return nil, fail("inclusion", "entry %d: %v", i, err)
			}
			seq, err := checkLeaf(e)
			if err != nil {
				return nil, fail("schema", "entry %d: %v", i, err)
			}
			if seq != i {
				return nil, fail("seq", "entry %d has seq %d (gap or reorder)", i, seq)
			}
		}
	}
	// 3. Consistency between successive checkpoints (tree proofs computed from the head's tiles).
	for i := 0; i+1 < len(cps); i++ {
		old, nw := cps[i], cps[i+1]
		if old.tree.N == nw.tree.N || old.tree.N == 0 {
			continue
		}
		p, err := tlog.ProveTree(nw.tree.N, old.tree.N, tlog.TileHashReader(nw.tree, tr))
		if err != nil {
			return nil, fail("consistency", "%d -> %d: %v", old.tree.N, nw.tree.N, err)
		}
		if err := tlog.CheckTree(p, nw.tree.N, nw.tree.Hash, old.tree.N, old.tree.Hash); err != nil {
			return nil, fail("consistency", "%d -> %d: %v", old.tree.N, nw.tree.N, err)
		}
		// The older checkpoint's own partial tiles must still be served and rebuild its root.
		oh, err := tlog.TreeHash(old.tree.N, tlog.TileHashReader(old.tree, tr))
		if err != nil || oh != old.tree.Hash {
			return nil, fail("tree", "tiles for checkpoint %d do not rebuild its root (%v)", old.tree.N, err)
		}
	}

	return &report{entries: N, checkpoints: len(cps), cosigned: len(t.pq) > 0}, nil
}

func hexKeyID(id uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)
	return hex.EncodeToString(b)
}
