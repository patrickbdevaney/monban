//! Cedar evaluation: load + validate at startup, then decide PDP-1 requests.
//!
//! Decision mapping (fail closed, ARCHITECTURE §3.5 "an error in a forbid yields Deny"): a request that does not
//! build or does not conform to the schema (unknown type, missing context attribute, bad entity data) is `Error`;
//! an evaluation in which **any** policy errored (Cedar skips erroring policies, so an erroring `forbid` would
//! otherwise be ignored) is `Error`; otherwise Cedar's Allow/Deny. The host turns `Error` into Deny (F6).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema, ValidationMode, Validator,
};
use monban_authz::pdp::{PdpRequest, Uid, Value};
use monban_types::Decision;

/// A validated policy set and its schema.
#[derive(Debug)]
pub struct Engine {
    policies: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
}

/// What Cedar itself said, for diagnostics and the oracle's differential (`eval`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    /// `Allow`/`Deny` from Cedar, or why no Cedar decision was reached.
    pub raw: String,
}

impl Engine {
    /// Parse the schema and policies and validate (strict mode). Any parse or validation error refuses.
    /// Returns the engine and the warnings (printed by the caller).
    pub fn load(policy_src: &str, schema_src: &str) -> Result<(Self, Vec<String>), String> {
        let (schema, warns) = Schema::from_cedarschema_str(schema_src).map_err(|e| format!("schema: {e}"))?;
        let mut warnings: Vec<String> = warns.map(|w| format!("schema warning: {w}")).collect();
        let policies = PolicySet::from_str(policy_src).map_err(|e| format!("policies: {e}"))?;
        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        let errors: Vec<String> = result.validation_errors().map(|e| format!("validation error: {e}")).collect();
        warnings.extend(result.validation_warnings().map(|w| format!("validation warning: {w}")));
        if !errors.is_empty() || !result.validation_passed() {
            return Err(errors.join("\n"));
        }
        Ok((Self { policies, schema, authorizer: Authorizer::new() }, warnings))
    }

    /// Number of policies (for the startup line).
    pub fn policy_count(&self) -> usize {
        self.policies.policies().count()
    }

    /// Decide a decoded PDP-1 request.
    pub fn decide(&self, req: &PdpRequest) -> Verdict {
        match self.build(req) {
            Ok((r, e)) => self.finish(&r, &e),
            Err(why) => Verdict { decision: Decision::Error, raw: why },
        }
    }

    /// Decide a request given in Cedar's own formats (uid literals, context and entities JSON). This path shares
    /// nothing with the PDP-1 codec, so the oracle can compare the two.
    pub fn decide_json(&self, p: &str, a: &str, r: &str, context: &str, entities: &str) -> Verdict {
        let built = (|| -> Result<(Request, Entities), String> {
            let p = EntityUid::from_str(p).map_err(|e| format!("principal: {e}"))?;
            let a = EntityUid::from_str(a).map_err(|e| format!("action: {e}"))?;
            let r = EntityUid::from_str(r).map_err(|e| format!("resource: {e}"))?;
            let ctx = Context::from_json_str(context, Some((&self.schema, &a))).map_err(|e| format!("context: {e}"))?;
            let ents = Entities::from_json_str(entities, Some(&self.schema)).map_err(|e| format!("entities: {e}"))?;
            let req = Request::new(p, a, r, ctx, Some(&self.schema)).map_err(|e| format!("request: {e}"))?;
            Ok((req, ents))
        })();
        match built {
            Ok((r, e)) => self.finish(&r, &e),
            Err(why) => Verdict { decision: Decision::Error, raw: why },
        }
    }

    fn finish(&self, req: &Request, ents: &Entities) -> Verdict {
        let resp = self.authorizer.is_authorized(req, &self.policies, ents);
        let errors = resp.diagnostics().errors().count();
        let cedar = match resp.decision() {
            cedar_policy::Decision::Allow => Decision::Allow,
            cedar_policy::Decision::Deny => Decision::Deny,
        };
        let raw = format!("cedar={cedar:?} errors={errors}");
        if errors > 0 { Verdict { decision: Decision::Error, raw } } else { Verdict { decision: cedar, raw } }
    }

    fn build(&self, req: &PdpRequest) -> Result<(Request, Entities), String> {
        let principal = uid(&req.principal)?;
        let action = uid(&req.action)?;
        let resource = uid(&req.resource)?;
        let ctx = Context::from_pairs(fields(&req.context)?).map_err(|e| format!("context: {e}"))?;
        let mut ents = Vec::with_capacity(req.entities.len());
        for e in &req.entities {
            let attrs: HashMap<String, RestrictedExpression> = fields(&e.attrs)?.into_iter().collect();
            let parents: HashSet<EntityUid> = e.parents.iter().map(uid).collect::<Result<_, _>>()?;
            ents.push(Entity::new(uid(&e.uid)?, attrs, parents).map_err(|e| format!("entity: {e}"))?);
        }
        let ents = Entities::from_entities(ents, Some(&self.schema)).map_err(|e| format!("entities: {e}"))?;
        let r =
            Request::new(principal, action, resource, ctx, Some(&self.schema)).map_err(|e| format!("request: {e}"))?;
        Ok((r, ents))
    }
}

fn uid(u: &Uid) -> Result<EntityUid, String> {
    let ty = EntityTypeName::from_str(&u.ty).map_err(|e| format!("entity type {:?}: {e}", u.ty))?;
    Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(&u.id)))
}

fn fields(fs: &[(String, Value)]) -> Result<Vec<(String, RestrictedExpression)>, String> {
    fs.iter().map(|(k, v)| Ok((k.clone(), expr(v)?))).collect()
}

fn expr(v: &Value) -> Result<RestrictedExpression, String> {
    Ok(match v {
        Value::Bool(b) => RestrictedExpression::new_bool(*b),
        Value::Long(n) => RestrictedExpression::new_long(*n),
        Value::Str(s) => RestrictedExpression::new_string(s.clone()),
        Value::Entity(u) => RestrictedExpression::new_entity_uid(uid(u)?),
        Value::Set(xs) => RestrictedExpression::new_set(xs.iter().map(expr).collect::<Result<Vec<_>, _>>()?),
        Value::Record(fs) => RestrictedExpression::new_record(fields(fs)?).map_err(|e| format!("record: {e}"))?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;
    use monban_authz::pdp::EntityData;

    const SCHEMA: &str = r#"
        namespace App {
            entity Role;
            entity User in [Role] { level: Long };
            entity Doc { owner: User };
            action read appliesTo { principal: [User], resource: [Doc], context: { amount: Long } };
        }
    "#;
    const POLICIES: &str = r#"
        permit(principal in App::Role::"reader", action == App::Action::"read", resource);
        forbid(principal, action, resource) when { context.amount + 9223372036854775807 > 0 && context.amount > 0 };
    "#;

    fn req(user: &str, roles: &[&str], amount: i64) -> PdpRequest {
        PdpRequest {
            principal: Uid::new("App::User", user),
            action: Uid::new("App::Action", "read"),
            resource: Uid::new("App::Doc", "d"),
            context: vec![("amount".into(), Value::Long(amount))],
            entities: vec![
                EntityData {
                    uid: Uid::new("App::User", user),
                    attrs: vec![("level".into(), Value::Long(1))],
                    parents: roles.iter().map(|r| Uid::new("App::Role", r)).collect(),
                },
                EntityData {
                    uid: Uid::new("App::Doc", "d"),
                    attrs: vec![("owner".into(), Value::Entity(Uid::new("App::User", user)))],
                    parents: vec![],
                },
            ],
        }
    }

    #[test]
    fn decisions_and_fail_closed_mapping() {
        let (e, _) = Engine::load(POLICIES, SCHEMA).unwrap();
        assert_eq!(e.decide(&req("a", &["reader"], 0)).decision, Decision::Allow);
        assert_eq!(e.decide(&req("a", &[], 0)).decision, Decision::Deny);
        // amount = 1: the forbid overflows, Cedar skips it and says Allow; we say Error.
        let v = e.decide(&req("a", &["reader"], 1));
        assert_eq!(v.decision, Decision::Error);
        assert!(v.raw.contains("cedar=Allow"), "{}", v.raw);
        // Schema violations: missing context attribute, unknown entity type.
        let mut r = req("a", &["reader"], 0);
        r.context.clear();
        assert_eq!(e.decide(&r).decision, Decision::Error);
        let mut r = req("a", &["reader"], 0);
        r.resource = Uid::new("App::Nope", "x");
        assert_eq!(e.decide(&r).decision, Decision::Error);
        let mut r = req("a", &["reader"], 0);
        r.principal = Uid::new("not a type", "x");
        assert_eq!(e.decide(&r).decision, Decision::Error);
    }

    #[test]
    fn json_path_agrees() {
        let (e, _) = Engine::load(POLICIES, SCHEMA).unwrap();
        let ents = r#"[{"uid":{"type":"App::User","id":"a"},"attrs":{"level":1},"parents":[{"type":"App::Role","id":"reader"}]},
                       {"uid":{"type":"App::Doc","id":"d"},"attrs":{"owner":{"__entity":{"type":"App::User","id":"a"}}},"parents":[]}]"#;
        let v =
            e.decide_json(r#"App::User::"a""#, r#"App::Action::"read""#, r#"App::Doc::"d""#, r#"{"amount":0}"#, ents);
        assert_eq!(v.decision, Decision::Allow, "{}", v.raw);
    }

    #[test]
    fn refuses_invalid_policy_sets() {
        // Unknown attribute: strict validation error.
        assert!(Engine::load("permit(principal, action, resource) when { principal.nope == 1 };", SCHEMA).is_err());
        // Parse error.
        assert!(Engine::load("permit(principal", SCHEMA).is_err());
        // Schema error.
        assert!(Engine::load(POLICIES, "entity ;").is_err());
    }
}
