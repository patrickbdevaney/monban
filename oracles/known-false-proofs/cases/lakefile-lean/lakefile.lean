import Lake
open Lake DSL
/- EXPLOIT: a `lakefile.lean` (Lake DSL) is Lean CODE evaluated when Lake configures the
   build. Arbitrary IO can run before a single proof is checked -- an attacker-controlled
   build script. The gate forbids lakefile.lean entirely and requires lakefile.toml
   (parsed natively, no code execution). This marker shows configure-time execution. -/
#eval IO.println "CONFIGURE-TIME CODE EXECUTION (benign marker)"
package kf where
  leanOptions := #[]
@[default_target] lean_lib KF where
  roots := #[`KF]
