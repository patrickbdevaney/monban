//! Render → re-parse with an independent minimal OpenMetrics 1.0 exposition parser.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::*;

// ------------------------------------------------------------------ minimal OpenMetrics parser

#[derive(Debug, Default)]
struct PFamily {
    name: String,
    kind: Option<String>,
    unit: Option<String>,
    help: Option<String>,
    samples: Vec<PSample>,
}

#[derive(Debug, Clone, PartialEq)]
struct PSample {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

fn metric_name_ok(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

fn label_name_ok(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Unescapes an OpenMetrics escaped-string; only `\\`, `\"`, `\n` are legal escapes; bare `"` is illegal.
fn unescape(s: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                other => return Err(format!("bad escape \\{other:?}")),
            },
            '"' => return Err("unescaped quote".into()),
            c => out.push(c),
        }
    }
    Ok(out)
}

type Labels = Vec<(String, String)>;

fn parse_labels(s: &str) -> Result<(Labels, &str), String> {
    // s starts right after '{'
    let mut labels: Labels = Vec::new();
    let mut rest = s;
    if let Some(r) = rest.strip_prefix('}') {
        return Ok((labels, r));
    }
    loop {
        let eq = rest.find('=').ok_or("label without '='")?;
        let name = &rest[..eq];
        if !label_name_ok(name) {
            return Err(format!("bad label name {name:?}"));
        }
        rest = rest[eq + 1..].strip_prefix('"').ok_or("label value not quoted")?;
        let mut end = None;
        let mut esc = false;
        for (i, c) in rest.char_indices() {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                end = Some(i);
                break;
            }
        }
        let end = end.ok_or("unterminated label value")?;
        let value = unescape(&rest[..end])?;
        if labels.iter().any(|(k, _)| k == name) {
            return Err(format!("duplicate label {name}"));
        }
        labels.push((name.to_owned(), value));
        rest = &rest[end + 1..];
        if let Some(r) = rest.strip_prefix('}') {
            return Ok((labels, r));
        }
        rest = rest.strip_prefix(',').ok_or("expected ',' or '}' after label")?;
    }
}

fn parse_value(s: &str) -> Result<f64, String> {
    match s {
        "+Inf" => Ok(f64::INFINITY),
        "-Inf" => Ok(f64::NEG_INFINITY),
        "NaN" => Ok(f64::NAN),
        _ if s.is_empty() || s.contains(|c: char| c.is_ascii_alphabetic() && c != 'e' && c != 'E') => {
            Err(format!("bad value {s:?}"))
        }
        _ => s.parse::<f64>().map_err(|e| format!("bad value {s:?}: {e}")),
    }
}

fn sample_belongs(fam: &PFamily, sample: &str) -> bool {
    match fam.kind.as_deref() {
        Some("counter") => sample == format!("{}_total", fam.name) || sample == format!("{}_created", fam.name),
        _ => sample == fam.name,
    }
}

fn parse(text: &str) -> Result<Vec<PFamily>, String> {
    let body = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = body.split('\n').collect();
    match lines.last() {
        Some(&"# EOF") => {}
        _ => return Err("last line is not '# EOF'".into()),
    }
    let mut fams: Vec<PFamily> = Vec::new();
    for (n, line) in lines[..lines.len() - 1].iter().enumerate() {
        let ln = n + 1;
        if line.is_empty() {
            return Err(format!("line {ln}: empty line"));
        }
        if let Some(meta) = line.strip_prefix("# ") {
            if meta == "EOF" {
                return Err(format!("line {ln}: '# EOF' before the end"));
            }
            let mut parts = meta.splitn(3, ' ');
            let (kw, name, arg) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next());
            if !metric_name_ok(name) {
                return Err(format!("line {ln}: bad metric name {name:?}"));
            }
            let cur_is = fams.last().is_some_and(|f| f.name == name);
            if !cur_is {
                if fams.iter().any(|f| f.name == name) {
                    return Err(format!("line {ln}: family {name} not contiguous"));
                }
                fams.push(PFamily { name: name.to_owned(), ..PFamily::default() });
            }
            let fam = fams.last_mut().unwrap();
            if !fam.samples.is_empty() {
                return Err(format!("line {ln}: metadata after samples for {name}"));
            }
            match (kw, arg) {
                ("TYPE", Some(t)) => {
                    if fam.kind.is_some() {
                        return Err(format!("line {ln}: second TYPE for {name}"));
                    }
                    let ok =
                        ["counter", "gauge", "histogram", "gaugehistogram", "stateset", "info", "summary", "unknown"];
                    if !ok.contains(&t) {
                        return Err(format!("line {ln}: bad type {t}"));
                    }
                    fam.kind = Some(t.to_owned());
                }
                ("UNIT", Some(u)) => {
                    if fam.unit.is_some() {
                        return Err(format!("line {ln}: second UNIT for {name}"));
                    }
                    if !name.ends_with(&format!("_{u}")) {
                        return Err(format!("line {ln}: {name} does not end with unit {u}"));
                    }
                    fam.unit = Some(u.to_owned());
                }
                ("HELP", h) => {
                    if fam.help.is_some() {
                        return Err(format!("line {ln}: second HELP for {name}"));
                    }
                    fam.help = Some(unescape(h.unwrap_or(""))?);
                }
                _ => return Err(format!("line {ln}: bad metadata line")),
            }
            continue;
        }
        if line.starts_with('#') {
            return Err(format!("line {ln}: bare comment"));
        }
        // sample
        let name_end = line.find(['{', ' ']).ok_or(format!("line {ln}: no value"))?;
        let sname = &line[..name_end];
        if !metric_name_ok(sname) {
            return Err(format!("line {ln}: bad metric name {sname:?}"));
        }
        let (labels, rest) = if line[name_end..].starts_with('{') {
            parse_labels(&line[name_end + 1..]).map_err(|e| format!("line {ln}: {e}"))?
        } else {
            (Vec::new(), &line[name_end..])
        };
        let rest = rest.strip_prefix(' ').ok_or(format!("line {ln}: expected space before value"))?;
        let mut vs = rest.split(' ');
        let value = parse_value(vs.next().unwrap_or("")).map_err(|e| format!("line {ln}: {e}"))?;
        if let Some(ts) = vs.next() {
            parse_value(ts).map_err(|e| format!("line {ln}: timestamp {e}"))?;
        }
        if vs.next().is_some() {
            return Err(format!("line {ln}: trailing tokens"));
        }
        let belongs = fams.last().is_some_and(|f| sample_belongs(f, sname));
        if !belongs {
            // a sample with no metadata starts an untyped family named after the sample
            if fams.iter().any(|f| sample_belongs(f, sname) || f.name == sname) {
                return Err(format!("line {ln}: family of {sname} not contiguous"));
            }
            fams.push(PFamily { name: sname.to_owned(), ..PFamily::default() });
        }
        let fam = fams.last_mut().unwrap();
        if fam.samples.iter().any(|s| s.name == sname && s.labels == labels) {
            return Err(format!("line {ln}: duplicate series"));
        }
        if fam.kind.as_deref() == Some("counter") && (value.is_nan() || value < 0.0) {
            return Err(format!("line {ln}: negative or NaN counter"));
        }
        fam.samples.push(PSample { name: sname.to_owned(), labels, value });
    }
    Ok(fams)
}

// ------------------------------------------------------------------ parser negative controls

#[test]
fn parser_rejects_malformed_expositions() {
    let good = "# TYPE a counter\n# HELP a h\na_total 1\n# TYPE b gauge\nb{x=\"1\"} 2\n# EOF\n";
    parse(good).unwrap();
    let bad = [
        ("no eof", "# TYPE a gauge\na 1\n"),
        ("after eof", "# TYPE a gauge\na 1\n# EOF\na 2\n"),
        ("two types", "# TYPE a gauge\n# TYPE a gauge\na 1\n# EOF\n"),
        ("not contiguous", "# TYPE a gauge\na 1\n# TYPE b gauge\nb 1\n# TYPE a gauge\n# EOF\n"),
        ("not contiguous sample", "# TYPE a gauge\na 1\n# TYPE b gauge\nb 1\na 2\n# EOF\n"),
        ("bad name", "# TYPE 1a gauge\n1a 1\n# EOF\n"),
        ("bad name char", "a-b 1\n# EOF\n"),
        ("bad escape", "a{x=\"\\t\"} 1\n# EOF\n"),
        ("raw quote", "a{x=\"q\"q\"} 1\n# EOF\n"),
        ("counter no total", "# TYPE a counter\na 1\n# EOF\n"),
        ("unit mismatch", "# TYPE a gauge\n# UNIT a seconds\na 1\n# EOF\n"),
        ("meta after sample", "# TYPE a gauge\na 1\n# HELP a h\n# EOF\n"),
        ("dup series", "# TYPE a gauge\na 1\na 2\n# EOF\n"),
        ("bad value", "# TYPE a gauge\na one\n# EOF\n"),
        ("comment", "# hello\n# EOF\n"),
        ("neg counter", "# TYPE a counter\na_total -1\n# EOF\n"),
    ];
    for (why, text) in bad {
        assert!(parse(text).is_err(), "parser accepted malformed input ({why}): {text:?}");
    }
}

// ------------------------------------------------------------------ registry output

fn find<'a>(fams: &'a [PFamily], name: &str) -> &'a PFamily {
    fams.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("family {name} missing"))
}

#[test]
fn golden_families_present_with_zero_values() {
    let text = Registry::new().render().unwrap();
    let fams = parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    assert_eq!(fams.len(), GOLDEN.len(), "unexpected families in {text}");
    for g in GOLDEN {
        let f = find(&fams, g.name);
        assert_eq!(f.kind.as_deref(), Some(g.kind.as_str()), "{}", g.name);
        assert_eq!(f.help.as_deref(), Some(g.help));
        assert_eq!(f.unit.as_deref(), g.unit);
        assert!(!f.samples.is_empty(), "{} has no samples", g.name);
        for s in &f.samples {
            assert_eq!(s.value, 0.0, "{} not zero", g.name);
            let keys: Vec<&str> = s.labels.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(keys, g.labels, "{}", g.name);
            let want = match g.kind {
                MetricType::Counter => format!("{}_total", g.name),
                MetricType::Gauge => g.name.to_owned(),
            };
            assert_eq!(s.name, want);
        }
    }
    assert_eq!(find(&fams, "monban_admission_rejects").samples.len(), AdmissionStage::ALL.len());
    assert_eq!(find(&fams, "monban_budget_debits").samples.len(), BudgetScope::ALL.len());
    assert_eq!(find(&fams, "monban_cert_seconds_to_expiry").samples.len(), CertSlot::ALL.len());
    assert!(text.ends_with("\n# EOF\n"));
}

#[test]
fn golden_covers_architecture_list_and_matches_registry_order() {
    let names: Vec<&str> = GOLDEN.iter().map(|g| g.name).collect();
    for want in [
        "monban_admission_rejects",
        "monban_budget_debits",
        "monban_crash_budget_trips",
        "monban_cert_seconds_to_expiry",
        "monban_fips_status",
        "monban_config_generation_hash",
        "monban_config_lkg_fallbacks",
        "monban_upgrade_forced_closes",
    ] {
        assert!(names.contains(&want), "{want} missing from GOLDEN");
    }
    let reg: Vec<FamilyDesc> = Registry::new().families().into_iter().map(|f| f.desc).collect();
    assert_eq!(reg, GOLDEN);
}

#[test]
fn stage_labels_match_admission_wire_names() {
    // monban_admission::Stage::as_str, ARCHITECTURE §3.4.
    let names: Vec<&str> = AdmissionStage::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names, ["S0", "S1", "S2", "S3", "S3A", "S4", "S5", "S6"]);
    for (i, s) in AdmissionStage::ALL.iter().enumerate() {
        assert_eq!(s.index(), i);
    }
    for (i, s) in BudgetScope::ALL.iter().enumerate() {
        assert_eq!(s.index(), i);
    }
    for (i, s) in CertSlot::ALL.iter().enumerate() {
        assert_eq!(s.index(), i);
    }
}

#[test]
fn values_round_trip() {
    let r = Registry::new();
    r.admission_rejects.inc(AdmissionStage::S3A);
    r.admission_rejects.add(AdmissionStage::S0, 5);
    r.budget_debits.add(BudgetScope::Identity, 7);
    r.crash_budget_trips.inc();
    r.cert_seconds_to_expiry.set(CertSlot::Serving, -42);
    r.cert_seconds_to_expiry.set(CertSlot::Admin, 86_400);
    r.set_fips_active(true);
    r.set_config_hash(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0xff, 0xff]);
    r.config_lkg_fallbacks.add(2);
    r.upgrade_forced_closes.add(3);
    let text = r.render().unwrap();
    let fams = parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    let val = |fam: &str, label: Option<&str>| -> f64 {
        find(&fams, fam).samples.iter().find(|s| s.labels.first().map(|(_, v)| v.as_str()) == label).unwrap().value
    };
    assert_eq!(val("monban_admission_rejects", Some("S3A")), 1.0);
    assert_eq!(val("monban_admission_rejects", Some("S0")), 5.0);
    assert_eq!(val("monban_admission_rejects", Some("S1")), 0.0);
    assert_eq!(val("monban_budget_debits", Some("identity")), 7.0);
    assert_eq!(val("monban_crash_budget_trips", None), 1.0);
    assert_eq!(val("monban_cert_seconds_to_expiry", Some("serving")), -42.0);
    assert_eq!(val("monban_cert_seconds_to_expiry", Some("admin")), 86_400.0);
    assert_eq!(val("monban_fips_status", None), 1.0);
    assert_eq!(val("monban_config_generation_hash", None), 0xdead_beef_0102_u64 as f64);
    assert_eq!(val("monban_config_lkg_fallbacks", None), 2.0);
    assert_eq!(val("monban_upgrade_forced_closes", None), 3.0);
    r.set_config_hash(&[0x01]);
    assert_eq!(r.config_generation_hash.get(), 0x0100_0000_0000);
    r.set_fips_active(false);
    assert_eq!(r.fips_status.get(), 0);
}

#[test]
fn counter_saturates_instead_of_wrapping() {
    let c = Counter::new();
    c.add(u64::MAX - 1);
    c.add(5);
    assert_eq!(c.get(), u64::MAX);
}

// ------------------------------------------------------------------ renderer rules

const fn desc(
    name: &'static str,
    kind: MetricType,
    unit: Option<&'static str>,
    labels: &'static [&'static str],
) -> FamilyDesc {
    FamilyDesc { name, kind, unit, help: "h", labels }
}

#[test]
fn label_values_and_help_are_escaped() {
    let nasty = "a\"b\\c\nd} x=\"y";
    let d = FamilyDesc { help: "line1\nline2 \\ \"q\"", ..desc("t_esc", MetricType::Gauge, None, &["v"]) };
    let fams = [Family { desc: d, samples: vec![Sample { labels: vec![("v", nasty)], value: Value::Signed(1) }] }];
    let text = render(&fams).unwrap();
    assert!(text.contains(r#"t_esc{v="a\"b\\c\nd} x=\"y"} 1"#), "{text}");
    assert!(text.contains(r#"# HELP t_esc line1\nline2 \\ \"q\""#), "{text}");
    assert_eq!(text.lines().count(), 4, "raw newline leaked: {text:?}");
    let p = parse(&text).unwrap();
    assert_eq!(p[0].samples[0].labels[0].1, nasty);
    assert_eq!(p[0].help.as_deref(), Some("line1\nline2 \\ \"q\""));
    assert_eq!(escape("plain"), "plain");
}

#[test]
fn unit_line_rendered_and_parses() {
    let fams = [Family {
        desc: desc("t_wait_seconds", MetricType::Gauge, Some("seconds"), &[]),
        samples: vec![Sample { labels: vec![], value: Value::Unsigned(3) }],
    }];
    let text = render(&fams).unwrap();
    assert_eq!(
        text,
        "# TYPE t_wait_seconds gauge\n# UNIT t_wait_seconds seconds\n# HELP t_wait_seconds h\nt_wait_seconds 3\n# EOF\n"
    );
    let p = parse(&text).unwrap();
    assert_eq!(p[0].unit.as_deref(), Some("seconds"));
}

#[test]
fn renderer_rejects_invalid_descriptors() {
    let one = |d: FamilyDesc, labels: Vec<(&'static str, &'static str)>, value: Value| {
        render(&[Family { desc: d, samples: vec![Sample { labels, value }] }])
    };
    let g = MetricType::Gauge;
    let c = MetricType::Counter;
    let u = Value::Unsigned(0);
    assert!(matches!(one(desc("1bad", g, None, &[]), vec![], u), Err(RenderError::BadMetricName(_))));
    assert!(matches!(one(desc("a-b", g, None, &[]), vec![], u), Err(RenderError::BadMetricName(_))));
    assert!(matches!(one(desc("", g, None, &[]), vec![], u), Err(RenderError::BadMetricName(_))));
    assert!(matches!(one(desc("x_total", c, None, &[]), vec![], u), Err(RenderError::ReservedSuffix(_))));
    assert!(matches!(one(desc("x_created", c, None, &[]), vec![], u), Err(RenderError::ReservedSuffix(_))));
    assert!(matches!(one(desc("x_bytes", g, Some("seconds"), &[]), vec![], u), Err(RenderError::BadUnit(_))));
    assert!(matches!(one(desc("xseconds", g, Some("seconds"), &[]), vec![], u), Err(RenderError::BadUnit(_))));
    assert!(matches!(one(desc("x", g, None, &["__r"]), vec![("__r", "v")], u), Err(RenderError::BadLabelName(_))));
    assert!(matches!(one(desc("x", g, None, &["a-b"]), vec![("a-b", "v")], u), Err(RenderError::BadLabelName(_))));
    assert!(matches!(one(desc("x", g, None, &["a"]), vec![("b", "v")], u), Err(RenderError::LabelMismatch(_))));
    assert!(matches!(one(desc("x", g, None, &["a"]), vec![], u), Err(RenderError::LabelMismatch(_))));
    assert!(matches!(one(desc("x", c, None, &[]), vec![], Value::Signed(-1)), Err(RenderError::NegativeCounter(_))));
    let d = desc("x", g, None, &[]);
    let s = Sample { labels: vec![], value: u };
    let dup_fam = [Family { desc: d, samples: vec![s.clone()] }, Family { desc: d, samples: vec![s.clone()] }];
    assert!(matches!(render(&dup_fam), Err(RenderError::DuplicateFamily(_))));
    let dup_series = [Family { desc: d, samples: vec![s.clone(), s] }];
    assert!(matches!(render(&dup_series), Err(RenderError::DuplicateSeries(_))));
    assert_eq!(render(&[]).unwrap(), "# EOF\n");
}

// ------------------------------------------------------------------ concurrency

#[test]
fn concurrent_increments_are_not_lost() {
    const THREADS: u64 = 8;
    const ITERS: u64 = 20_000;
    let r = Registry::new();
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let r = &r;
            s.spawn(move || {
                for i in 0..ITERS {
                    r.admission_rejects.inc(AdmissionStage::S3A);
                    r.budget_debits.add(BudgetScope::Ip, 2);
                    r.crash_budget_trips.inc();
                    r.cert_seconds_to_expiry.set(CertSlot::Serving, (t * ITERS + i) as i64);
                    if i % 1000 == 0 {
                        // scrapes concurrent with writers must always parse
                        let text = r.render().unwrap();
                        parse(&text).unwrap();
                    }
                }
            });
        }
    });
    assert_eq!(r.admission_rejects.get(AdmissionStage::S3A), THREADS * ITERS);
    assert_eq!(r.admission_rejects.get(AdmissionStage::S3), 0);
    assert_eq!(r.budget_debits.get(BudgetScope::Ip), 2 * THREADS * ITERS);
    assert_eq!(r.crash_budget_trips.get(), THREADS * ITERS);
    let text = r.render().unwrap();
    assert!(text.contains(&format!("monban_admission_rejects_total{{stage=\"S3A\"}} {}\n", THREADS * ITERS)), "{text}");
}

#[test]
fn registry_is_sync_and_static_constructible() {
    static R: Registry = Registry::new();
    fn is_sync<T: Sync + Send>(_: &T) {}
    is_sync(&R);
    R.upgrade_forced_closes.inc();
    assert_eq!(R.upgrade_forced_closes.get(), 1);
}
