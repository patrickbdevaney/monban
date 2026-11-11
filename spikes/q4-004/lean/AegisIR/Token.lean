/-
Monban Tier-L capability token (macaroon-style HMAC chain over deterministic CBOR caveats).
Transcribed by r4 E01 (2026-10-25) from r3 node r3e05.l5-token-wire-format-lean (statements T1-T6).
Core Lean 4 only. HMAC is a PARAMETER `H` (not an `axiom`, not `opaque`): every theorem is universally quantified
over the MAC function, so no axiom enters the TCB; EUF-CMA of HMAC-SHA256 is an explicit, unproven assumption that
lives OUTSIDE Lean and gives T5 its security meaning.

Transcription decisions that CHANGE or SHARPEN the r3 prose spec (flagged, each is a spec decision to ratify):
  D1 res_prefix is a PATH-SEGMENT prefix over `List String`, not a string prefix: a string prefix "/t/1" would admit
     "/t/10". The Rust verifier must split the canonical path into segments exactly as `segments` here.
  D2 ops is a bitmask; a request op-set `r.ops` is allowed iff r.ops ⊆ mask, i.e. `r.ops &&& mask = r.ops`.
  D3 depth_left: the r3 prose "appending is allowed only if depth_left > 0" is NOT enforceable at append time (the
     holder appends offline with no issuer involvement). It is enforced at VERIFY time: number of caveats after the
     mint prefix ≤ minted depth. Appended `depth` caveats can only lower the effective bound (min).
  D4 a tool caveat with an argument constraint for a key absent from the request DENIES (fail-closed).
-/
namespace AegisIR.Token

abbrev Bytes := List UInt8

inductive ArgVal where
  | int : Int → ArgVal
  | str : String → ArgVal
  deriving DecidableEq, Repr

inductive ArgCon where
  | exact : ArgVal → ArgCon
  | range : Int → Int → ArgCon          -- inclusive, ints only
  | oneOf : List ArgVal → ArgCon
  deriving DecidableEq, Repr

def ArgCon.sat : ArgCon → ArgVal → Bool
  | .exact v, x => decide (x = v)
  | .range lo hi, .int x => decide (lo ≤ x) && decide (x ≤ hi)
  | .range _ _, .str _ => false
  | .oneOf vs, x => vs.contains x

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

/-- Mint shape: [aud a, exp e, depth d] ++ appended.  (Issuer-side MAX_TTL check is `e ≤ now_mint + MAX_TTL`.) -/
def WellMinted (cs : List Caveat) (a : String) (e d : Nat) : Prop :=
  ∃ tail, cs = .aud a :: .exp e :: .depth d :: tail

/-- Effective expiry = min over all exp caveats. -/
def effExp : List Caveat → Option Nat
  | [] => none
  | .exp e :: cs => some (match effExp cs with | some e' => min e e' | none => e)
  | _ :: cs => effExp cs

def minOpt : Option Nat → Option Nat → Option Nat
  | some a, some b => some (min a b)
  | some a, none => some a
  | none, b => b

/-- Verify-time depth rule (D3): caveats appended after the 3-element mint prefix ≤ minted depth, and every
    appended depth caveat is respected via min. -/
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

/-- Constant-time comparison is a Rust obligation; in the model it is plain equality. -/
def verify (K : Bytes) (t : Token) (r : Req) : Bool :=
  decide (macChain H enc K t.kid t.nonce t.caveats = t.tag) && denote t.caveats r && depthOk t.caveats

/-- Holder-side attenuation: extend the chain with no key. -/
def attenuate (t : Token) (c : Caveat) : Token :=
  { t with caveats := t.caveats ++ [c], tag := H t.tag (enc c) }
end MAC

-- ------------------------------------------------------------------------------------------- theorems
/-- T1 attenuation monotonicity. -/
theorem attenuation_mono (cs : List Caveat) (c : Caveat) (r : Req) :
    denote (cs ++ [c]) r = true → denote cs r = true := by
  intro h
  simp only [denote, List.all_append, Bool.and_eq_true] at h
  exact h.1

/-- T1' general form: any suffix. -/
theorem attenuation_mono_append (cs ds : List Caveat) (r : Req) :
    denote (cs ++ ds) r = true → denote cs r = true := by
  intro h
  simp only [denote, List.all_append, Bool.and_eq_true] at h
  exact h.1

/-- T2 audience binding. -/
theorem aud_bound (cs : List Caveat) (a : String) (e d : Nat) (r : Req)
    (hm : WellMinted cs a e d) (hd : denote cs r = true) : r.aud = a := by
  obtain ⟨tail, rfl⟩ := hm
  simp [denote, sat] at hd
  exact hd.1

/-- T3a expiry under the minted exp. -/
theorem expiry_minted (cs : List Caveat) (a : String) (e d : Nat) (r : Req)
    (hm : WellMinted cs a e d) (hd : denote cs r = true) : r.now < e := by
  obtain ⟨tail, rfl⟩ := hm
  simp [denote, sat] at hd
  exact hd.2.1

theorem effExp_append (cs ds : List Caveat) : effExp (cs ++ ds) = minOpt (effExp cs) (effExp ds) := by
  induction cs with
  | nil => cases h : effExp ds <;> simp [effExp, minOpt, h]
  | cons c cs ih =>
    cases c <;> simp only [List.cons_append, effExp, ih]
    case exp e =>
      cases h1 : effExp cs <;> cases h2 : effExp ds <;> simp [minOpt, Nat.min_assoc]

/-- T3b appended exp caveats only lower the effective expiry. -/
theorem effExp_append_exp (cs : List Caveat) (e : Nat) :
    effExp (cs ++ [.exp e]) = some (match effExp cs with | some x => min x e | none => e) := by
  rw [effExp_append]; cases effExp cs <;> simp [effExp, minOpt]

/-- T3c every exp caveat (in particular the effective one) is enforced. -/
theorem expiry_effective (cs : List Caveat) (r : Req) :
    ∀ e, effExp cs = some e → denote cs r = true → r.now < e := by
  induction cs with
  | nil => intro e h; simp [effExp] at h
  | cons c cs ih =>
    intro e he hd
    simp only [denote, List.all_cons, Bool.and_eq_true] at hd
    have hd' : denote cs r = true := hd.2
    cases c with
    | exp x =>
      simp only [effExp] at he
      have hx : r.now < x := by simpa [sat] using hd.1
      cases h : effExp cs with
      | none => simp [h] at he; omega
      | some y => simp [h] at he; have := ih y h hd'; omega
    | _ => simp only [effExp] at he; exact ih e he hd'

theorem effDepth_append (cs ds : List Caveat) : effDepth (cs ++ ds) = minOpt (effDepth cs) (effDepth ds) := by
  induction cs with
  | nil => cases h : effDepth ds <;> simp [effDepth, minOpt, h]
  | cons c cs ih =>
    cases c <;> simp only [List.cons_append, effDepth, ih]
    case depth e =>
      cases h1 : effDepth cs <;> cases h2 : effDepth ds <;> simp [minOpt, Nat.min_assoc]

/-- T4a effective depth never increases under attenuation (and stays defined). -/
theorem effDepth_append_le (cs : List Caveat) (c : Caveat) (d : Nat) (h0 : effDepth cs = some d) :
    ∃ d', effDepth (cs ++ [c]) = some d' ∧ d' ≤ d := by
  rw [effDepth_append, h0]
  cases h : effDepth [c] with
  | none => exact ⟨d, by simp [minOpt], Nat.le_refl d⟩
  | some k => exact ⟨min d k, by simp [minOpt], Nat.min_le_left d k⟩

/-- T4b verify-time depth rule is monotone: removing the last appended caveat keeps depthOk
    (so the bound cannot be satisfied by appending MORE caveats). -/
theorem depthOk_bound (cs : List Caveat) (d : Nat) (h0 : effDepth cs = some d) (h : depthOk cs = true) :
    cs.length ≤ 3 + d := by
  simp [depthOk, h0] at h; exact h

/-- T5 verify iff (definitional; security content comes only from EUF-CMA of H, assumed outside Lean). -/
theorem verify_iff (H : Bytes → Bytes → Bytes) (enc : Caveat → Bytes) (K : Bytes) (t : Token) (r : Req) :
    verify H enc K t r = true ↔
      (macChain H enc K t.kid t.nonce t.caveats = t.tag ∧ denote t.caveats r = true ∧ depthOk t.caveats = true) := by
  simp [verify, Bool.and_eq_true, and_assoc]

/-- T5' holder attenuation preserves MAC validity without the key (functional correctness of the chain). -/
theorem attenuate_mac (H : Bytes → Bytes → Bytes) (enc : Caveat → Bytes) (K : Bytes) (t : Token) (c : Caveat)
    (hv : macChain H enc K t.kid t.nonce t.caveats = t.tag) :
    macChain H enc K t.kid t.nonce (attenuate H enc t c).caveats = (attenuate H enc t c).tag := by
  simp [attenuate, macChain, List.foldl_append] at *
  rw [hv]

/-- T5'' attenuation never widens: an attenuated token that verifies implies the original's caveats hold. -/
theorem attenuate_narrows (H : Bytes → Bytes → Bytes) (enc : Caveat → Bytes) (K : Bytes) (t : Token)
    (c : Caveat) (r : Req) (h : verify H enc K (attenuate H enc t c) r = true) : denote t.caveats r = true := by
  rw [verify_iff] at h
  exact attenuation_mono t.caveats c r h.2.1

/-- T6 canonical codec contract (proved for cborrs by EverParse; HERE only its consequence is derived):
    if parse ∘ enc = some, then enc is injective, so distinct caveats never MAC to the same chain input. -/
structure Codec where
  enc   : Caveat → Bytes
  parse : Bytes → Option Caveat
  parse_enc : ∀ c, parse (enc c) = some c
  enc_parse : ∀ b c, parse b = some c → enc c = b

theorem enc_injective (C : Codec) : ∀ c₁ c₂, C.enc c₁ = C.enc c₂ → c₁ = c₂ := by
  intro c₁ c₂ h
  have h1 := C.parse_enc c₁
  have h2 := C.parse_enc c₂
  rw [h] at h1
  rw [h1] at h2
  exact Option.some.inj h2

theorem parse_canonical (C : Codec) (b : Bytes) (c : Caveat) (h : C.parse b = some c) : C.enc c = b :=
  C.enc_parse b c h

end AegisIR.Token
