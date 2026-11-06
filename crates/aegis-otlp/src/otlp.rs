//! OpenMetrics families -> OTLP JSON `Metric` objects, and the request envelopes (opentelemetry-proto JSON
//! encoding: lowerCamelCase keys, integer enums, 64-bit integers as decimal strings).
//!
//! Mapping (oracles/otlp-export/README.md):
//! - counter `x` (samples `x_total`) -> `sum`, CUMULATIVE (`aggregationTemporality: 2`), monotonic, name `x`;
//! - `x_created` -> `startTimeUnixNano`; without it, the exporter's start time (fixed for the process);
//! - gauge and unknown -> `gauge`;
//! - histogram -> `histogram`, CUMULATIVE, finite `le` bounds ascending, de-cumulated `bucketCounts`, `le` dropped;
//! - HELP -> `description`, UNIT -> `unit`, labels -> string attributes, integer tokens -> exact `asInt`.

use std::collections::HashMap;

use crate::jsonw;
use crate::om::{Family, Kind, Num, OmError};

/// Fixed per-export context.
#[derive(Clone, Copy, Debug)]
pub struct Times {
    /// `timeUnixNano` of every point in this export.
    pub now: u64,
    /// Exporter start: `startTimeUnixNano` of cumulative series without `_created`.
    pub start: u64,
}

fn sorted(labels: &[(String, String)]) -> Vec<(String, String)> {
    let mut v = labels.to_vec();
    v.sort();
    v
}

fn attrs(out: &mut String, labels: &[(String, String)]) {
    jsonw::key(out, "attributes");
    out.push('[');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        jsonw::kv_str(out, k, v);
    }
    out.push(']');
}

fn value(out: &mut String, v: Num) {
    match v {
        Num::Int(i) => {
            jsonw::key(out, "asInt");
            jsonw::int(out, i);
        }
        Num::Double(d) => {
            jsonw::key(out, "asDouble");
            jsonw::f64(out, d);
        }
    }
}

fn header(out: &mut String, f: &Family) {
    out.push('{');
    jsonw::key(out, "name");
    jsonw::str(out, &f.name);
    out.push(',');
    jsonw::key(out, "description");
    jsonw::str(out, &f.help);
    if !f.unit.is_empty() {
        out.push(',');
        jsonw::key(out, "unit");
        jsonw::str(out, &f.unit);
    }
    out.push(',');
}

fn number_point(out: &mut String, labels: &[(String, String)], start: Option<u64>, now: u64, v: Num) {
    out.push('{');
    attrs(out, labels);
    if let Some(s) = start {
        out.push_str(",\"startTimeUnixNano\":");
        jsonw::int(out, s.min(now));
    }
    out.push_str(",\"timeUnixNano\":");
    jsonw::int(out, now);
    out.push(',');
    value(out, v);
    out.push('}');
}

/// A cumulative monotonic `sum` metric with a single unlabelled integer point (exporter self-metrics).
pub fn self_counter(out: &mut String, name: &str, description: &str, t: Times, v: u64) {
    out.push('{');
    jsonw::key(out, "name");
    jsonw::str(out, name);
    out.push(',');
    jsonw::key(out, "description");
    jsonw::str(out, description);
    out.push_str(",\"sum\":{\"dataPoints\":[");
    number_point(out, &[], Some(t.start), t.now, Num::Int(i64::try_from(v).unwrap_or(i64::MAX)));
    out.push_str("],\"aggregationTemporality\":2,\"isMonotonic\":true}}");
}

fn counter(out: &mut String, f: &Family, t: Times) -> Result<bool, OmError> {
    let mut created: HashMap<Vec<(String, String)>, u64> = HashMap::new();
    for s in f.samples.iter().filter(|s| s.suffix == "_created") {
        created.insert(sorted(&s.labels), crate::om::created_ns(&s.token)?);
    }
    let pts: Vec<_> = f.samples.iter().filter(|s| s.suffix == "_total").collect();
    if pts.is_empty() {
        return Ok(false);
    }
    header(out, f);
    out.push_str("\"sum\":{\"dataPoints\":[");
    for (i, s) in pts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let start = created.get(&sorted(&s.labels)).copied().unwrap_or(t.start);
        number_point(out, &s.labels, Some(start), t.now, s.value);
    }
    out.push_str("],\"aggregationTemporality\":2,\"isMonotonic\":true}}");
    Ok(true)
}

fn gauge(out: &mut String, f: &Family, t: Times) -> bool {
    let pts: Vec<_> = f.samples.iter().filter(|s| s.suffix.is_empty()).collect();
    if pts.is_empty() {
        return false;
    }
    header(out, f);
    out.push_str("\"gauge\":{\"dataPoints\":[");
    for (i, s) in pts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        number_point(out, &s.labels, None, t.now, s.value);
    }
    out.push_str("]}}");
    true
}

#[derive(Default)]
struct Hist {
    labels: Vec<(String, String)>,
    buckets: Vec<(f64, u64)>,
    count: Option<u64>,
    sum: Option<f64>,
    created: Option<u64>,
}

fn whole(v: Num) -> Result<u64, OmError> {
    match v {
        Num::Int(i) => u64::try_from(i).map_err(|_| OmError("negative histogram count")),
        Num::Double(d) if d.is_finite() && d >= 0.0 && d.fract() == 0.0 && d < 1.8e19 => Ok(d as u64),
        Num::Double(_) => Err(OmError("histogram count is not a whole number")),
    }
}

fn histogram(out: &mut String, f: &Family, t: Times) -> Result<bool, OmError> {
    let mut series: Vec<Hist> = Vec::new();
    let mut index: HashMap<Vec<(String, String)>, usize> = HashMap::new();
    for s in &f.samples {
        let labels: Vec<(String, String)> = s.labels.iter().filter(|(k, _)| k != "le").cloned().collect();
        let key = sorted(&labels);
        let idx = match index.get(&key) {
            Some(&i) => i,
            None => {
                series.push(Hist { labels, ..Hist::default() });
                index.insert(key, series.len() - 1);
                series.len() - 1
            }
        };
        let h = series.get_mut(idx).ok_or(OmError("internal"))?;
        match s.suffix {
            "_bucket" => {
                let le = s.labels.iter().find(|(k, _)| k == "le").ok_or(OmError("bucket without le"))?;
                let le = crate::om::number(&le.1)?.as_f64();
                if le.is_nan() {
                    return Err(OmError("bucket le is NaN"));
                }
                h.buckets.push((le, whole(s.value)?));
            }
            "_count" => h.count = Some(whole(s.value)?),
            "_sum" => h.sum = Some(s.value.as_f64()),
            "_created" => h.created = Some(crate::om::created_ns(&s.token)?),
            _ => return Err(OmError("bad histogram sample")),
        }
    }
    if series.is_empty() {
        return Ok(false);
    }
    header(out, f);
    out.push_str("\"histogram\":{\"dataPoints\":[");
    for (i, h) in series.iter_mut().enumerate() {
        h.buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
        if h.buckets.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0 || b.1 < a.1)) {
            return Err(OmError("histogram buckets duplicate or not cumulative"));
        }
        let Some(&(last_le, inf_count)) = h.buckets.last() else {
            return Err(OmError("histogram series without buckets"));
        };
        if last_le != f64::INFINITY {
            return Err(OmError("histogram without +Inf bucket"));
        }
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        attrs(out, &h.labels);
        out.push_str(",\"startTimeUnixNano\":");
        jsonw::int(out, h.created.unwrap_or(t.start).min(t.now));
        out.push_str(",\"timeUnixNano\":");
        jsonw::int(out, t.now);
        out.push_str(",\"count\":");
        jsonw::int(out, h.count.unwrap_or(inf_count));
        if let Some(s) = h.sum {
            out.push_str(",\"sum\":");
            jsonw::f64(out, s);
        }
        out.push_str(",\"bucketCounts\":[");
        let mut prev = 0u64;
        for (j, &(_, c)) in h.buckets.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            jsonw::int(out, c.saturating_sub(prev));
            prev = c;
        }
        out.push_str("],\"explicitBounds\":[");
        let mut first = true;
        for &(le, _) in h.buckets.iter().filter(|(le, _)| le.is_finite()) {
            if !first {
                out.push(',');
            }
            first = false;
            jsonw::f64(out, le);
        }
        out.push_str("]}");
    }
    out.push_str("],\"aggregationTemporality\":2}}");
    Ok(true)
}

/// Append every mapped family as comma-separated `Metric` objects. Returns the number written. Any mapping error
/// rejects the whole exposition (the caller exports nothing from it).
pub fn metrics(out: &mut String, fams: &[Family], t: Times) -> Result<usize, OmError> {
    let mut n = 0usize;
    for f in fams {
        let mark = out.len();
        if n > 0 {
            out.push(',');
        }
        let wrote = match f.kind {
            Kind::Counter => counter(out, f, t)?,
            Kind::Gauge | Kind::Unknown => gauge(out, f, t),
            Kind::Histogram => histogram(out, f, t)?,
            Kind::Skipped => false,
        };
        if wrote {
            n += 1;
        } else {
            out.truncate(mark);
        }
    }
    Ok(n)
}

/// The shared Resource and scope.
#[derive(Clone, Debug)]
pub struct Envelope {
    resource: String,
    scope: String,
}

impl Envelope {
    /// `service.name` first, then the extra string attributes.
    pub fn new(service_name: &str, extra: &[(String, String)]) -> Self {
        let mut r = String::from("{\"attributes\":[");
        jsonw::kv_str(&mut r, "service.name", service_name);
        for (k, v) in extra {
            r.push(',');
            jsonw::kv_str(&mut r, k, v);
        }
        r.push_str("]}");
        let mut s = String::from("{\"name\":\"aegis-otlp\",\"version\":");
        jsonw::str(&mut s, env!("CARGO_PKG_VERSION"));
        s.push('}');
        Self { resource: r, scope: s }
    }

    /// `ExportMetricsServiceRequest` around comma-separated `Metric` objects.
    pub fn metrics_request(&self, metrics: &str) -> String {
        format!(
            "{{\"resourceMetrics\":[{{\"resource\":{},\"scopeMetrics\":[{{\"scope\":{},\"metrics\":[{metrics}]}}]}}]}}",
            self.resource, self.scope
        )
    }

    /// `ExportLogsServiceRequest` around already-encoded `LogRecord` objects.
    pub fn logs_request<'a>(&self, records: impl Iterator<Item = &'a String>) -> String {
        let mut out = format!(
            "{{\"resourceLogs\":[{{\"resource\":{},\"scopeLogs\":[{{\"scope\":{},\"logRecords\":[",
            self.resource, self.scope
        );
        for (i, r) in records.enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(r);
        }
        out.push_str("]}]}]}");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_decumulates() {
        let t = b"# TYPE h histogram\nh_bucket{r=\"a\",le=\"0.5\"} 9\nh_bucket{r=\"a\",le=\"0.05\"} 5\nh_bucket{r=\"a\",le=\"+Inf\"} 10\nh_count{r=\"a\"} 10\nh_sum{r=\"a\"} 1.875\n# EOF\n";
        let fams = crate::om::parse(t).unwrap_or_default();
        let mut out = String::new();
        let n = metrics(&mut out, &fams, Times { now: 10, start: 5 });
        assert_eq!(n, Ok(1));
        assert!(out.contains("\"bucketCounts\":[\"5\",\"4\",\"1\"],\"explicitBounds\":[0.05,0.5]"), "{out}");
        assert!(out.contains("\"count\":\"10\",\"sum\":1.875"), "{out}");
    }

    #[test]
    fn counter_maps_to_sum() {
        let t = b"# TYPE c counter\nc_total{a=\"1\"} 4\n# EOF\n";
        let fams = crate::om::parse(t).unwrap_or_default();
        let mut out = String::new();
        assert_eq!(metrics(&mut out, &fams, Times { now: 10, start: 5 }), Ok(1));
        assert!(out.starts_with("{\"name\":\"c\",\"description\":\"\",\"sum\":{\"dataPoints\":[{\"attributes\":[{\"key\":\"a\",\"value\":{\"stringValue\":\"1\"}}],\"startTimeUnixNano\":\"5\",\"timeUnixNano\":\"10\",\"asInt\":\"4\"}],\"aggregationTemporality\":2,\"isMonotonic\":true}}"), "{out}");
    }
}
