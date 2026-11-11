# Oracle subjects

Thin tool-layer binaries (`layer = "tool"`, never linked into monban) that expose a production crate over an
oracle's `--subject` protocol, e.g. `oracles/admission-props/run --subject 'target/release/admission-subject'`.
They may depend on any workspace crate; nothing may depend on them.
