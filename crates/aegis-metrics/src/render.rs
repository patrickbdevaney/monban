//! OpenMetrics 1.0 text renderer.
//!
//! Per family: `# TYPE`, then `# UNIT` (if any), then `# HELP`, then the samples. Counter samples are named
//! `<family>_total`; gauge samples use the family name. Label values and HELP text are escaped (`\\`, `\"`, `\n`).
//! The exposition ends with `# EOF\n`. Families are contiguous by construction (each is written in one go).

use crate::{FamilyDesc, MetricType};

/// A sample value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// Non-negative integer (valid for counters and gauges).
    Unsigned(u64),
    /// Signed integer (gauges; a counter rejects a negative value).
    Signed(i64),
}

/// One sample: label pairs (in [`FamilyDesc::labels`] order) and a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample<'a> {
    /// `(name, value)` pairs; the value is escaped on output.
    pub labels: Vec<(&'a str, &'a str)>,
    /// The value.
    pub value: Value,
}

/// A family snapshot ready to render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Family<'a> {
    /// Descriptor.
    pub desc: FamilyDesc,
    /// Samples.
    pub samples: Vec<Sample<'a>>,
}

/// Why a family set could not be rendered. Nothing is emitted on error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// Metric name outside `[a-zA-Z_:][a-zA-Z0-9_:]*`.
    BadMetricName(String),
    /// Label name outside `[a-zA-Z_][a-zA-Z0-9_]*`, or reserved (`__` prefix).
    BadLabelName(String),
    /// Unit outside `[a-zA-Z0-9_:]+`, or the family name does not end with `_<unit>`.
    BadUnit(String),
    /// Counter family name ends in a reserved suffix (`_total`, `_created`).
    ReservedSuffix(String),
    /// The same family name appears twice.
    DuplicateFamily(String),
    /// A sample's label names differ from the descriptor's.
    LabelMismatch(String),
    /// Two samples in a family have the same label set.
    DuplicateSeries(String),
    /// Negative counter value.
    NegativeCounter(String),
}

fn is_metric_name(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

fn is_label_name(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with("__")
}

/// OpenMetrics escaping for label values and HELP text: `\` → `\\`, `"` → `\"`, LF → `\n`.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn validate(fams: &[Family<'_>]) -> Result<(), RenderError> {
    let mut seen: Vec<&str> = Vec::with_capacity(fams.len());
    for f in fams {
        let d = &f.desc;
        let name = d.name.to_owned();
        if !is_metric_name(d.name) {
            return Err(RenderError::BadMetricName(name));
        }
        if seen.contains(&d.name) {
            return Err(RenderError::DuplicateFamily(name));
        }
        seen.push(d.name);
        if d.kind == MetricType::Counter && (d.name.ends_with("_total") || d.name.ends_with("_created")) {
            return Err(RenderError::ReservedSuffix(name));
        }
        if let Some(u) = d.unit {
            let unit_ok = !u.is_empty() && u.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
            if !unit_ok || !d.name.strip_suffix(u).is_some_and(|p| p.ends_with('_')) {
                return Err(RenderError::BadUnit(name));
            }
        }
        if let Some(bad) = d.labels.iter().find(|l| !is_label_name(l)) {
            return Err(RenderError::BadLabelName((*bad).to_owned()));
        }
        for (i, s) in f.samples.iter().enumerate() {
            if !s.labels.iter().map(|(k, _)| *k).eq(d.labels.iter().copied()) {
                return Err(RenderError::LabelMismatch(name));
            }
            if f.samples.iter().take(i).any(|p| p.labels == s.labels) {
                return Err(RenderError::DuplicateSeries(name));
            }
            if d.kind == MetricType::Counter && matches!(s.value, Value::Signed(v) if v < 0) {
                return Err(RenderError::NegativeCounter(name));
            }
        }
    }
    Ok(())
}

/// Renders `fams` as an OpenMetrics 1.0 exposition ending in `# EOF\n`.
///
/// # Errors
/// Any [`RenderError`]; the descriptors and samples are validated before anything is written.
pub fn render(fams: &[Family<'_>]) -> Result<String, RenderError> {
    validate(fams)?;
    let mut out = String::new();
    for f in fams {
        let d = &f.desc;
        out.push_str("# TYPE ");
        out.push_str(d.name);
        out.push(' ');
        out.push_str(d.kind.as_str());
        out.push('\n');
        if let Some(u) = d.unit {
            out.push_str("# UNIT ");
            out.push_str(d.name);
            out.push(' ');
            out.push_str(u);
            out.push('\n');
        }
        out.push_str("# HELP ");
        out.push_str(d.name);
        out.push(' ');
        out.push_str(&escape(d.help));
        out.push('\n');
        for s in &f.samples {
            out.push_str(d.name);
            if d.kind == MetricType::Counter {
                out.push_str("_total");
            }
            if !s.labels.is_empty() {
                out.push('{');
                for (i, (k, v)) in s.labels.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(k);
                    out.push_str("=\"");
                    out.push_str(&escape(v));
                    out.push('"');
                }
                out.push('}');
            }
            out.push(' ');
            match s.value {
                Value::Unsigned(v) => out.push_str(&v.to_string()),
                Value::Signed(v) => out.push_str(&v.to_string()),
            }
            out.push('\n');
        }
    }
    out.push_str("# EOF\n");
    Ok(out)
}
