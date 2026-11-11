/-
Monban TLS key-exchange group selection model: Select(model) of spec/SPEC_INVARIANTS.md section F and its
2026-11-04 addendum (PLAN-6 D3). Group selection only: the F12 oracle's two admission steps that run before it
(no common version -> alert 70, no common sigalg -> alert 49) are outside this model.

`select p ch` is the first server record for profile `p` and a TLS 1.3 ClientHello reduced to the two fields group
selection reads: supported_groups (client order) and the groups that carry a key_share. Modelled on rustls 0.23.46
client-order selection: sel := the first group in ch.groups that is in p.kx; none -> Alert 40 (handshake_failure);
sel in ch.key_shares -> ServerHello sel; otherwise HRR sel. The serverOrder selector is the PreferServerOrder
backport (first group of p.kx in ch.groups, otherwise identical); no F12 profile uses it today.

It matches `fn model` in oracles/hrr-verdicts/src/main.rs; oracles/select-drt checks that the compiled `select`
and that function agree on generated ClientHellos (rung R4 model + R2 correspondence). This is a model: it is not
a proof about rustls code, which is trusted, not verified (SECURITY_CLAIMS.md).

Profile table = the eight F8 profile names. F12 rows: FIPS-FLOOR and FIPS-CMVP both take the F12 `FIPS` row (same
group list; they differ in the linked module, P-PQ5, which selection does not read); P-PQ-REQUIRED is F12
`PQ-REQUIRED`. Group lists are copied from tls/verdicts.toml `kx_groups` in configured order; select-drt checks the
copy against the file on every run.
-/
namespace AegisIR.Select

/-- A TLS NamedGroup codepoint (RFC 8446 section 4.2.7). -/
abbrev Group := Nat

/-- Server group-selection rule. -/
inductive Selector where
  | clientOrder
  | serverOrder
  deriving DecidableEq, Repr

/-- The part of a profile group selection reads: its selector and its ordered group list. -/
structure Profile where
  selector : Selector
  kx : List Group
  deriving Repr

/-- The two ClientHello fields group selection reads. -/
structure ClientHello where
  /-- supported_groups, in client preference order. -/
  groups : List Group
  /-- groups for which the key_share extension carries an entry. -/
  key_shares : List Group
  deriving Repr

/-- First server record: ServerHello on g, HelloRetryRequest selecting g, or a fatal alert (40 handshake_failure). -/
inductive Outcome where
  | serverHello (g : Group)
  | hrr (g : Group)
  | alert (code : Nat)
  deriving DecidableEq, Repr

/-- The group the server selects, if any. -/
def pick (sel : Selector) (kx : List Group) (ch : ClientHello) : Option Group :=
  match sel with
  | .clientOrder => ch.groups.find? (fun g => kx.contains g)
  | .serverOrder => kx.find? (fun g => ch.groups.contains g)

/-- Select(model). -/
def select (p : Profile) (ch : ClientHello) : Outcome :=
  match pick p.selector p.kx ch with
  | none => .alert 40
  | some g => if ch.key_shares.contains g then .serverHello g else .hrr g

/-- Classical (non-PQ) groups of P-PQ1 as stated in the section F addendum: X25519, P-256, P-384. -/
def classical : List Group := [0x001D, 0x0017, 0x0018]

-- ------------------------------------------------------------------------------------------------ profile table

/-- The eight F8 profiles. -/
inductive ProfileId where
  | publicWeb
  | pqRequired
  | universal
  | bsiAlt
  | cnsa
  | fipsFloor
  | fipsPqRequired
  | fipsCmvp
  deriving DecidableEq, Repr

def allProfiles : List ProfileId :=
  [.publicWeb, .pqRequired, .universal, .bsiAlt, .cnsa, .fipsFloor, .fipsPqRequired, .fipsCmvp]

/-- F8 name of each profile. -/
def ProfileId.name : ProfileId → String
  | .publicWeb => "P-PUBLIC-WEB"
  | .pqRequired => "P-PQ-REQUIRED"
  | .universal => "P-UNIVERSAL"
  | .bsiAlt => "P-BSI-ALT"
  | .cnsa => "P-CNSA"
  | .fipsFloor => "FIPS-FLOOR"
  | .fipsPqRequired => "FIPS-PQ-REQUIRED"
  | .fipsCmvp => "FIPS-CMVP"

/-- F12 (tls/verdicts.toml) profile row each F8 profile takes its group list from. -/
def ProfileId.f12Row : ProfileId → String
  | .publicWeb => "P-PUBLIC-WEB"
  | .pqRequired => "PQ-REQUIRED"
  | .universal => "P-UNIVERSAL"
  | .bsiAlt => "P-BSI-ALT"
  | .cnsa => "P-CNSA"
  | .fipsFloor => "FIPS"
  | .fipsPqRequired => "FIPS-PQ-REQUIRED"
  | .fipsCmvp => "FIPS"

/-- Profile table, F12 `selector` and `kx_groups` (codepoints from [codepoints.groups]). -/
def ProfileId.profile : ProfileId → Profile
  | .publicWeb => ⟨.clientOrder, [0x11EC, 0x11ED, 0x11EB, 0x001D, 0x0017]⟩
  | .pqRequired => ⟨.clientOrder, [0x11EC]⟩
  | .universal => ⟨.clientOrder, [0x11ED]⟩
  | .bsiAlt => ⟨.clientOrder, [0x11ED, 0x11EB]⟩
  | .cnsa => ⟨.clientOrder, [0x0202]⟩
  | .fipsFloor => ⟨.clientOrder, [0x11EB, 0x0017, 0x0018]⟩
  | .fipsPqRequired => ⟨.clientOrder, [0x11EB]⟩
  | .fipsCmvp => ⟨.clientOrder, [0x11EB, 0x0017, 0x0018]⟩

/-- The pq-required profiles (P-PQ1): exactly those whose group list has no classical group. -/
def pqRequiredProfiles : List ProfileId := [.pqRequired, .universal, .bsiAlt, .cnsa, .fipsPqRequired]

-- ------------------------------------------------------------------------------------------------ lemmas

theorem pick_mem (sel : Selector) (kx : List Group) (ch : ClientHello) (g : Group) :
    pick sel kx ch = some g → g ∈ kx ∧ g ∈ ch.groups := by
  intro h
  cases sel with
  | clientOrder =>
    simp only [pick] at h
    exact ⟨List.contains_iff_mem.mp (List.find?_some h), List.mem_of_find?_eq_some h⟩
  | serverOrder =>
    simp only [pick] at h
    exact ⟨List.mem_of_find?_eq_some h, List.contains_iff_mem.mp (List.find?_some h)⟩

theorem pick_none (sel : Selector) (kx : List Group) (ch : ClientHello) :
    pick sel kx ch = none ↔ ∀ g, g ∈ ch.groups → g ∉ kx := by
  cases sel with
  | clientOrder =>
    simp only [pick, List.find?_eq_none]
    constructor
    · intro h g hg hk
      exact h g hg (List.contains_iff_mem.mpr hk)
    · intro h g hg hc
      exact h g hg (List.contains_iff_mem.mp (by simpa using hc))
  | serverOrder =>
    simp only [pick, List.find?_eq_none]
    constructor
    · intro h g hg hk
      exact h g hk (List.contains_iff_mem.mpr hg)
    · intro h g hk hc
      exact h g (List.contains_iff_mem.mp (by simpa using hc)) hk

theorem select_pick (p : Profile) (ch : ClientHello) (g : Group) :
    (select p ch = .serverHello g ∨ select p ch = .hrr g) → pick p.selector p.kx ch = some g := by
  unfold select
  cases pick p.selector p.kx ch with
  | none => simp
  | some x =>
    simp only
    split <;> simp_all

-- ------------------------------------------------------------------------------------------------ theorems (F1 §F)

/-- P-PQ2 (selection half): a negotiated group is in the profile's group list and in the client's
supported_groups. -/
theorem select_in_profile (p : Profile) (ch : ClientHello) (g : Group) :
    (select p ch = .serverHello g ∨ select p ch = .hrr g) → g ∈ p.kx ∧ g ∈ ch.groups :=
  fun h => pick_mem _ _ _ _ (select_pick p ch g h)

/-- Alert 40 iff no group of ch.groups is in p.kx. -/
theorem alert_iff_empty_intersection (p : Profile) (ch : ClientHello) :
    select p ch = .alert 40 ↔ ∀ g, g ∈ ch.groups → g ∉ p.kx := by
  rw [← pick_none]
  unfold select
  cases pick p.selector p.kx ch with
  | none => simp
  | some x =>
    simp only
    split <;> simp

/-- P-PQ1: if p.kx contains no classical group, no outcome names a classical group, and a client offering only
classical groups gets Alert 40. -/
theorem pq_required_no_classical (p : Profile) (hp : ∀ g, g ∈ p.kx → g ∉ classical) (ch : ClientHello) :
    (∀ g, (select p ch = .serverHello g ∨ select p ch = .hrr g) → g ∉ classical) ∧
    ((∀ g, g ∈ ch.groups → g ∈ classical) → select p ch = .alert 40) := by
  constructor
  · intro g h
    exact hp g (select_in_profile p ch g h).1
  · intro hc
    rw [alert_iff_empty_intersection]
    intro g hg hk
    exact hp g hk (hc g hg)

/-- HRR only when the client sent no key share for the selected group. -/
theorem hrr_only_if_no_share (p : Profile) (ch : ClientHello) (g : Group) :
    select p ch = .hrr g → g ∉ ch.key_shares := by
  intro h hs
  unfold select at h
  cases hpk : pick p.selector p.kx ch with
  | none => rw [hpk] at h; cases h
  | some x =>
    rw [hpk] at h
    simp only at h
    split at h
    · cases h
    · rename_i hn
      cases h
      exact hn (List.contains_iff_mem.mpr hs)

/-- P-UNIVERSAL (kx = [0x11ED]): every ServerHello or HRR outcome names 0x11ED. -/
theorem universal_only_11ED (ch : ClientHello) (g : Group) :
    (select ProfileId.universal.profile ch = .serverHello g ∨ select ProfileId.universal.profile ch = .hrr g) →
      g = 0x11ED := by
  intro h
  have := (select_in_profile _ ch g h).1
  simpa [ProfileId.profile] using this

-- ------------------------------------------------------------------------------------------------ corollaries

/-- A ServerHello only when the client sent a key share for the selected group. -/
theorem sh_only_if_share (p : Profile) (ch : ClientHello) (g : Group) :
    select p ch = .serverHello g → g ∈ ch.key_shares := by
  intro h
  unfold select at h
  cases hpk : pick p.selector p.kx ch with
  | none => rw [hpk] at h; cases h
  | some x =>
    rw [hpk] at h
    simp only at h
    split at h
    · rename_i hc
      cases h
      exact List.contains_iff_mem.mp hc
    · cases h

/-- Selection emits no alert other than 40. -/
theorem alert_code_40 (p : Profile) (ch : ClientHello) (c : Nat) : select p ch = .alert c → c = 40 := by
  intro h
  unfold select at h
  cases hpk : pick p.selector p.kx ch with
  | none => rw [hpk] at h; cases h; rfl
  | some x =>
    rw [hpk] at h
    simp only at h
    split at h <;> cases h

/-- The table's pq-required list is exactly the F8 profiles whose group list has no classical group, so
pq_required_no_classical applies to each of them. -/
theorem pqRequired_table : ∀ p : ProfileId,
    p ∈ pqRequiredProfiles ↔ p.profile.kx.all (fun g => !classical.contains g) = true := by
  intro p
  cases p <;> decide

theorem pqRequired_hyp (p : ProfileId) (hp : p ∈ pqRequiredProfiles) :
    ∀ g, g ∈ p.profile.kx → g ∉ classical := by
  intro g hg hc
  have h := List.all_eq_true.mp ((pqRequired_table p).mp hp) g hg
  simp at h
  exact h hc

/-- Offering 0x11ED to P-UNIVERSAL always negotiates (never Alert 40). -/
theorem universal_offer_11ED (ch : ClientHello) (hm : 0x11ED ∈ ch.groups) :
    select ProfileId.universal.profile ch ≠ .alert 40 := by
  intro ha
  exact (alert_iff_empty_intersection _ ch).mp ha 0x11ED hm (by simp [ProfileId.profile])

end AegisIR.Select
