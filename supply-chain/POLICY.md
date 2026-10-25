# Supply-chain policy (spec-author decision record)

## cargo-vet: frozen baseline, monotone down (decided 2026-10-25)
SUPPLY_CHAIN G1 says "zero exemptions"; its own CI row says "vet 0 new unaudited, exemptions monotone down", and
the research baseline was 183/233 crates unaudited (3.66M lines). A Phase-2 probe of the minimal
hyper/h2/tokio/rustls/aws-lc stack found 63 of 81 crates uncovered by the six import sets (≈3.8M lines, dominated
by aws-lc-sys 2.09M, windows-sys, ring, tokio, libc). A solo operator cannot audit that before shipping, so:

1. `supply-chain/vet-baseline.txt` freezes the exempted `crate:version` set at the moment a dependency first enters
   the golden lock. Only the spec author may add to it, and only in the commit that adds the dependency, with a
   one-line reason per crate.
2. Gate `ci/vet-baseline.py`: every `[[exemptions.*]]` entry in supply-chain/config.toml must be in the baseline;
   the exemption count may never exceed the previous commit's; a crate already in the lock may not gain an exemption.
3. Version bumps of a baseline crate need an audit delta (`cargo vet diff`) or an import, never a new exemption:
   exemptions only decrease.
4. Coverage is reported as audited-or-imported / total crates and lines, never as "vetted".
5. Never `cargo vet trust` a publisher of a crate with build.rs or a proc-macro.
