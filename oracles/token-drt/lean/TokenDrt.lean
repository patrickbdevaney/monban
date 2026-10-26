/-
token-drt reference evaluator (core Lean 4 only, no imports beyond the prelude).

Section 1 is a COPY of the definitions in spec/AegisIR/Token.lean (theorems omitted), kept textually identical except
for two marked F5 extensions:
  X1 `ArgCon.strPrefix` (the wire's `argpred [3, tstr]`, not in Token.lean) and its `sat` case.
  X2 `shapeOk` / `countOk` (F5 mint-shape check and 1..64 caveats), conjoined in `verifyF5` below.
`run` checks that every non-extension line of section 1 still occurs verbatim in spec/AegisIR/Token.lean.

Section 2 instantiates the MAC parameter `H` with a FREE (injective) function: H k m = [0xA5] ++ len(k) ++ k ++ m,
and `enc` with an injective serialization. Under a free H, `macChain` equality holds iff key, kid ‖ nonce and the
caveat encodings are equal: the ideal-MAC (EUF-CMA) reading of T5. The Rust side uses real HMAC-SHA256; the two
agree except on an HMAC collision. K_aud is modelled as master ‖ "aegis-cap-v1" ‖ aud ‖ kid (the HKDF info string,
concatenated exactly as F5 specifies).

Section 3 parses the case lines (format in ../README.md) and prints `<id> <verify><denote><depthOk><shapeOk>`.
-/
namespace AegisIR.Token

-- BEGIN COPY (spec/AegisIR/Token.lean)
abbrev Bytes := List UInt8

inductive ArgVal where
  | int : Int → ArgVal
  | str : String → ArgVal
  deriving DecidableEq, Repr

inductive ArgCon where
  | exact : ArgVal → ArgCon
  | range : Int → Int → ArgCon          -- inclusive, ints only
  | oneOf : List ArgVal → ArgCon
  | strPrefix : String → ArgCon         -- EXTENSION X1
  deriving DecidableEq, Repr

def ArgCon.sat : ArgCon → ArgVal → Bool
  | .exact v, x => decide (x = v)
  | .range lo hi, .int x => decide (lo ≤ x) && decide (x ≤ hi)
  | .range _ _, .str _ => false
  | .oneOf vs, x => vs.contains x
  | .strPrefix p, .str s => p.isPrefixOf s   -- EXTENSION X1
  | .strPrefix _, .int _ => false           -- EXTENSION X1

inductive Caveat where
  | aud    : String → Caveat
  | exp    : Nat → Caveat
  | nbf    : Nat → Caveat
  | ops    : Nat → Caveat                    -- bitmask
  | res    : List String → Caveat            -- canonical path segments (D1)
  | cnf    : Bytes → Caveat                  -- holder key thumbprint (32 B in the wire format)
  | tenant : Bytes → Caveat                  -- 16 B in the wire format
  | tool   : String → List (String × ArgCon) → Caveat
  | depth  : Nat → Caveat                    -- depth_left
  deriving DecidableEq, Repr

structure Req where
  aud    : String
  ops    : Nat
  res    : List String
  tenant : Bytes
  holder : Bytes
  tool   : String
  args   : List (String × ArgVal)
  now    : Nat

def argsOk (r : Req) : List (String × ArgCon) → Bool
  | [] => true
  | (k, c) :: rest =>
    (match r.args.lookup k with
     | some v => c.sat v
     | none => false) && argsOk r rest                 -- D4

def sat (r : Req) : Caveat → Bool
  | .aud a => decide (r.aud = a)
  | .exp e => decide (r.now < e)
  | .nbf n => decide (n ≤ r.now)
  | .ops m => decide (r.ops &&& m = r.ops)              -- D2
  | .res p => p.isPrefixOf r.res                         -- D1
  | .cnf j => decide (r.holder = j)
  | .tenant t => decide (r.tenant = t)
  | .tool n as => decide (r.tool = n) && argsOk r as
  | .depth _ => true                                     -- structural; checked by `depthOk`

def denote (cs : List Caveat) (r : Req) : Bool := cs.all (sat r)

def effExp : List Caveat → Option Nat
  | [] => none
  | .exp e :: cs => some (match effExp cs with | some e' => min e e' | none => e)
  | _ :: cs => effExp cs

def minOpt : Option Nat → Option Nat → Option Nat
  | some a, some b => some (min a b)
  | some a, none => some a
  | none, b => b

def effDepth : List Caveat → Option Nat
  | [] => none
  | .depth d :: cs => some (match effDepth cs with | some d' => min d d' | none => d)
  | _ :: cs => effDepth cs

def depthOk (cs : List Caveat) : Bool :=
  match effDepth cs with
  | some d => decide (cs.length ≤ 3 + d)
  | none => false

structure Token where
  kid     : Bytes
  nonce   : Bytes
  caveats : List Caveat
  tag     : Bytes

section MAC
variable (H : Bytes → Bytes → Bytes) (enc : Caveat → Bytes)

def macChain (K : Bytes) (kid nonce : Bytes) (cs : List Caveat) : Bytes :=
  cs.foldl (fun t c => H t (enc c)) (H K (kid ++ nonce))

def verify (K : Bytes) (t : Token) (r : Req) : Bool :=
  decide (macChain H enc K t.kid t.nonce t.caveats = t.tag) && denote t.caveats r && depthOk t.caveats

def attenuate (t : Token) (c : Caveat) : Token :=
  { t with caveats := t.caveats ++ [c], tag := H t.tag (enc c) }
end MAC
-- END COPY

-- EXTENSION X2: F5 mint-shape check and caveat count.
def shapeOk : List Caveat → Bool
  | .aud _ :: .exp _ :: .depth _ :: _ => true
  | _ => false

def countOk (cs : List Caveat) : Bool := decide (1 ≤ cs.length) && decide (cs.length ≤ 64)

end AegisIR.Token

-- ================================================================== section 2: free MAC instantiation
namespace TokenDrt
open AegisIR.Token

def natBytes (n : Nat) : Bytes :=
  [UInt8.ofNat (n / 16777216 % 256), UInt8.ofNat (n / 65536 % 256), UInt8.ofNat (n / 256 % 256),
   UInt8.ofNat (n % 256)]

/-- Free MAC: injective in (k, m) because k is length-prefixed. -/
def freeH (k m : Bytes) : Bytes := [0xA5] ++ natBytes k.length ++ k ++ m

def strB (s : String) : Bytes := s.toUTF8.toList
def lp (b : Bytes) : Bytes := natBytes b.length ++ b
def lps (s : String) : Bytes := lp (strB s)
def natE (n : Nat) : Bytes := lps (toString n)
def intE (i : Int) : Bytes := lps (toString i)

def encVal : ArgVal → Bytes
  | .int i => [0] ++ intE i
  | .str s => [1] ++ lps s

def encCon : ArgCon → Bytes
  | .exact v => [0] ++ encVal v
  | .oneOf vs => [1] ++ natE vs.length ++ (vs.map encVal).foldl (· ++ ·) []
  | .range a b => [2] ++ intE a ++ intE b
  | .strPrefix p => [3] ++ lps p

/-- Injective caveat serialization (tag byte + length-prefixed fields). -/
def enc : Caveat → Bytes
  | .aud a => [0] ++ lps a
  | .exp e => [1] ++ natE e
  | .nbf n => [2] ++ natE n
  | .ops m => [3] ++ natE m
  | .res p => [4] ++ natE p.length ++ (p.map lps).foldl (· ++ ·) []
  | .cnf j => [5] ++ lp j
  | .tenant t => [6] ++ lp t
  | .tool n as => [7] ++ lps n ++ natE as.length ++ (as.map (fun (k, c) => lps k ++ encCon c)).foldl (· ++ ·) []
  | .depth d => [8] ++ natE d

def kAud (master : Nat) (aud : String) (kid : Bytes) : Bytes :=
  [UInt8.ofNat master] ++ strB "aegis-cap-v1" ++ strB aud ++ kid

def verifyF5 (keys : List (Bytes × Nat)) (t : Token) (r : Req) : Bool :=
  match keys.lookup t.kid with
  | none => false
  | some m => verify freeH enc (kAud m r.aud t.kid) t r && shapeOk t.caveats && countOk t.caveats

-- ================================================================== section 3: case parser
abbrev P := StateT (List String) Option

def tok : P String := do
  match (← get) with
  | [] => failure
  | t :: rest => set rest; pure t

def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def hexBytes : List Char → Option Bytes
  | [] => some []
  | a :: b :: rest => do
    let hi ← hexVal a
    let lo ← hexVal b
    let r ← hexBytes rest
    pure (UInt8.ofNat (hi * 16 + lo) :: r)
  | [_] => none

def optP {α} (o : Option α) : P α := match o with | some a => pure a | none => failure

/-- `x<hex>` raw bytes. -/
def pBytes : P Bytes := do
  let t ← tok
  match t.toList with
  | 'x' :: h => optP (hexBytes h)
  | _ => failure

/-- `s<hex>` UTF-8 string. -/
def pStr : P String := do
  let t ← tok
  match t.toList with
  | 's' :: h =>
    let b ← optP (hexBytes h)
    optP (String.fromUTF8? (ByteArray.mk b.toArray))
  | _ => failure

def pNat : P Nat := do optP (← tok).toNat?
def pInt : P Int := do optP (← tok).toInt?

def pList {α} (p : P α) : P (List α) := do
  let n ← pNat
  let rec go : Nat → P (List α)
    | 0 => pure []
    | k + 1 => do let a ← p; let r ← go k; pure (a :: r)
  go n

def pVal : P ArgVal := do
  match (← tok) with
  | "I" => return .int (← pInt)
  | "S" => return .str (← pStr)
  | _ => failure

def pCon : P ArgCon := do
  match (← tok) with
  | "q" => return .exact (← pVal)
  | "o" => return .oneOf (← pList pVal)
  | "r" => do let a ← pInt; let b ← pInt; return .range a b
  | "p" => return .strPrefix (← pStr)
  | _ => failure

/-- tenant uint → 8 big-endian bytes (the Lean model's `tenant : Bytes`). -/
def tenantBytes (n : Nat) : Bytes := (List.range 8).reverse.map (fun i => UInt8.ofNat (n / (256 ^ i) % 256))

def pCav : P Caveat := do
  match (← tok) with
  | "A" => return .aud (← pStr)
  | "E" => return .exp (← pNat)
  | "N" => return .nbf (← pNat)
  | "O" => return .ops (← pNat)
  | "R" => return .res (← pList pStr)
  | "C" => return .cnf (← pBytes)
  | "T" => return .tenant (tenantBytes (← pNat))
  | "L" => do
    let n ← pStr
    let as ← pList (do let k ← pStr; let c ← pCon; pure (k, c))
    return .tool n as
  | "D" => return .depth (← pNat)
  | _ => failure

def eraseAt {α} : List α → Nat → List α
  | [], _ => []
  | _ :: xs, 0 => xs
  | x :: xs, n + 1 => x :: eraseAt xs n

def setAt {α} : List α → Nat → α → List α
  | [], _, _ => []
  | _ :: xs, 0, a => a :: xs
  | x :: xs, n + 1, a => x :: setAt xs n a

def insAt {α} : List α → Nat → α → List α
  | xs, 0, a => a :: xs
  | [], _ + 1, _ => []          -- out of range: caller guarantees i ≤ length; marks a no-op below
  | x :: xs, n + 1, a => x :: insAt xs n a

def swapAt {α} (xs : List α) (i j : Nat) : List α :=
  match xs[i]?, xs[j]? with
  | some a, some b => setAt (setAt xs i b) j a
  | _, _ => xs

def pTamper (t : Token) : P Token := do
  match (← tok) with
  | "none" => return t
  | "droplast" => return { t with caveats := t.caveats.dropLast }
  | "drop" => do let i ← pNat; return { t with caveats := eraseAt t.caveats i }
  | "repl" => do let i ← pNat; let c ← pCav; return { t with caveats := setAt t.caveats i c }
  | "swap" => do let i ← pNat; let j ← pNat; return { t with caveats := swapAt t.caveats i j }
  | "ins" => do
    let i ← pNat; let c ← pCav
    if i ≤ t.caveats.length then return { t with caveats := insAt t.caveats i c } else return t
  | "app" => do let c ← pCav; return { t with caveats := t.caveats ++ [c] }
  | "tag" => return { t with tag := [0] }
  | "kid" => return { t with kid := (← pBytes) }
  | "nonce" => return { t with nonce := (← pBytes) }
  | _ => failure

def pReq : P Req := do
  let aud ← pStr
  let ops ← pNat
  let res ← pList pStr
  let tenant ← pNat
  let holder ← pBytes
  let tool ← pStr
  let args ← pList (do let k ← pStr; let v ← pVal; pure (k, v))
  let now ← pNat
  return { aud, ops, res, tenant := tenantBytes tenant, holder, tool, args, now }

def b2c (b : Bool) : Char := if b then '1' else '0'

def evalCase : P String := do
  let id ← tok
  let mMaster ← pNat
  let mAud ← pStr
  let mKid ← pBytes
  let mNonce ← pBytes
  let mintCs ← pList pCav
  let attCs ← pList pCav
  let base : Token :=
    { kid := mKid, nonce := mNonce, caveats := mintCs,
      tag := macChain freeH enc (kAud mMaster mAud mKid) mKid mNonce mintCs }
  let t0 := attCs.foldl (fun t c => attenuate freeH enc t c) base
  let t ← pTamper t0
  let keys ← pList (do let k ← pBytes; let m ← pNat; pure (k, m))
  let r ← pReq
  if !(← get).isEmpty then failure
  let v := verifyF5 keys t r
  return s!"{id} {String.ofList [b2c v, b2c (denote t.caveats r), b2c (depthOk t.caveats), b2c (shapeOk t.caveats)]}"

end TokenDrt

open TokenDrt in
partial def loop (h : IO.FS.Handle) (out : IO.FS.Stream) (buf : String) (n : Nat) : IO Unit := do
  let line ← h.getLine
  if line.isEmpty then
    out.putStr buf
    out.flush
    return
  let toks := (String.ofList (line.toList.filter (fun c => c != '\n' && c != '\r'))).splitOn " "
  let res := match evalCase.run toks with
    | some (s, _) => s
    | none => s!"{toks.headD "?"} PARSE_ERROR"
  let buf := buf ++ res ++ "\n"
  if n % 4096 == 4095 then
    out.putStr buf
    loop h out "" (n + 1)
  else
    loop h out buf (n + 1)

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
    let h ← IO.FS.Handle.mk path .read
    loop h (← IO.getStdout) "" 0
    return 0
  | _ =>
    IO.eprintln "usage: token-drt-lean <cases-file>"
    return 2
