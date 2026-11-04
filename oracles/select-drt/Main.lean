/-
select-drt Lean side: evaluates AegisIR.Select.select (spec/AegisIR/Select.lean, compiled as-is) on ClientHellos
read from stdin. Protocol (one line in, one line out, hex codepoints, `-` = empty list):

  in : <F8-PROFILE-NAME> <groups,comma,separated> <shares,comma,separated>     e.g.  P-PUBLIC-WEB 11ec,001d 001d
  out: sh <g> | hrr <g> | alert <code>                                          e.g.  hrr 11ec

  select-drt profiles              prints `<F8 name> <F12 row> <selector> <kx,...>` per profile (the runner checks the
                                   table against tls/verdicts.toml)
  select-drt [--mutate M]          M = order:<F8 name>  (that profile's selector flipped: the swapped-order mutant)
                                       share-ignored    (ServerHello even without a key share)
                                       kx-reversed:<F8 name> (group list reversed: an EQUIVALENT mutant under
                                                        client-order, expected to stay at 0 divergence)
Mutants exist only in this file; the spec module is never edited.
-/
import AegisIR.Select

open AegisIR.Select

def hex4 (n : Nat) : String :=
  let s := String.ofList (Nat.toDigits 16 n)
  String.ofList (List.replicate (4 - s.length) '0') ++ s

def parseHex (s : String) : Option Nat :=
  if s.isEmpty then none else
  s.foldl (fun acc c => acc.bind fun a =>
    if '0' ≤ c ∧ c ≤ '9' then some (a * 16 + (c.toNat - '0'.toNat))
    else if 'a' ≤ c ∧ c ≤ 'f' then some (a * 16 + (c.toNat - 'a'.toNat + 10))
    else if 'A' ≤ c ∧ c ≤ 'F' then some (a * 16 + (c.toNat - 'A'.toNat + 10))
    else none) (some 0)

def parseList (s : String) : Option (List Nat) :=
  if s == "-" then some [] else (s.splitOn ",").mapM parseHex

def selName : Selector → String
  | .clientOrder => "client-order"
  | .serverOrder => "server-order"

def flipSel : Selector → Selector
  | .clientOrder => .serverOrder
  | .serverOrder => .clientOrder

def showOutcome : Outcome → String
  | .serverHello g => s!"sh {hex4 g}"
  | .hrr g => s!"hrr {hex4 g}"
  | .alert c => s!"alert {c}"

def byName (n : String) : Option ProfileId := allProfiles.find? (·.name == n)

/-- The model actually evaluated: `select` itself unless a mutant is requested. -/
def evalWith (mutant : String) (pid : ProfileId) (ch : ClientHello) : Outcome :=
  if mutant == "order:" ++ pid.name then
    let p := pid.profile
    select { p with selector := flipSel p.selector } ch
  else if mutant == "kx-reversed:" ++ pid.name then
    let p := pid.profile
    select { p with kx := p.kx.reverse } ch
  else if mutant == "share-ignored" then
    match select pid.profile ch with
    | .hrr g => .serverHello g
    | o => o
  else
    select pid.profile ch

partial def loop (mutant : String) (inp : IO.FS.Stream) (out : IO.FS.Stream) : IO UInt32 := do
  let line ← inp.getLine
  if line.isEmpty then return 0
  let ws := (line.trimAscii.toString.splitOn " ").filter (· ≠ "")
  match ws with
  | [] => loop mutant inp out
  | [pn, gs, ss] =>
    match byName pn, parseList gs, parseList ss with
    | some pid, some g, some s =>
      out.putStrLn (showOutcome (evalWith mutant pid ⟨g, s⟩))
      loop mutant inp out
    | _, _, _ =>
      IO.eprintln s!"select-drt: bad line: {line.trimAscii}"
      return 2
  | _ =>
    IO.eprintln s!"select-drt: bad line: {line.trimAscii}"
    return 2

def main (args : List String) : IO UInt32 := do
  match args with
  | ["profiles"] =>
    for pid in allProfiles do
      let p := pid.profile
      IO.println s!"{pid.name} {pid.f12Row} {selName p.selector} {",".intercalate (p.kx.map hex4)}"
    return 0
  | [] => loop "" (← IO.getStdin) (← IO.getStdout)
  | ["--mutate", m] => loop m (← IO.getStdin) (← IO.getStdout)
  | _ =>
    IO.eprintln "usage: select-drt [profiles | --mutate M]  (cases on stdin)"
    return 2
