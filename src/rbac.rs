// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use ipnet::IpNet;

use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use tracing::{instrument, trace};
use xds::istio::security::Address as XdsAddress;
use xds::istio::security::Authorization as XdsRbac;
use xds::istio::security::Match;
use xds::istio::security::ServiceAccountMatch as XdsServiceAccountMatch;
use xds::istio::security::StringMatch as XdsStringMatch;
use xds::istio::security::string_match::MatchType;

use crate::identity::Identity;

use crate::state::workload::{WorkloadError, byte_to_ip};
use crate::strng::Strng;
use crate::{strng, xds};

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    pub name: Strng,
    pub namespace: Strng,
    pub scope: RbacScope,
    pub action: RbacAction,
    pub rules: Vec<Vec<Vec<RbacMatch>>>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct Connection {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub src_identity: Option<Identity>,
    pub dst_network: Strng,
}

struct OptionDisplay<'a, T>(&'a Option<T>);

impl<T: Display> Display for OptionDisplay<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => write!(f, "None"),
            Some(i) => write!(f, "{i}"),
        }
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})->{}",
            self.src,
            OptionDisplay(&self.src_identity),
            self.dst
        )
    }
}

impl Authorization {
    pub fn to_key(&self) -> Strng {
        let mut res = String::with_capacity(1 + self.namespace.len() + self.name.len());
        res.push_str(&self.namespace);
        res.push('/');
        res.push_str(&self.name);
        res.into()
    }

    #[instrument(level = "trace", skip_all, fields(policy=self.to_key().as_str()))]
    pub fn matches(&self, conn: &Connection) -> bool {
        let full_identity = conn.src_identity.as_ref();
        let id = conn
            .src_identity
            .as_ref()
            .map(|i| i.to_strng())
            .unwrap_or_default();
        let ns = conn
            .src_identity
            .as_ref()
            .map(|i| match i {
                Identity::Spiffe { namespace, .. } => namespace.to_owned(), // may be more clear if we use to_owned() to denote change from borrowed to owned
            })
            .unwrap_or_default();
        if self.rules.is_empty() {
            trace!(matches = false, "empty rules");
            return false;
        }
        // An Authorization Policy can have multiple rules
        // If ANY rule matches it's a match...
        for rule in self.rules.iter() {
            // Rule typically has 1-3 clauses (from,to,when)
            // If ALL clauses match, it is a match...
            let mut rule_match = true;
            for clause in rule.iter() {
                // We can have multiple mg (RbacMatch) in a clause, for example "Match ns=A,SA=B or ns=C"
                // So we need ANY mg to match...
                let mut clause_match = false;
                for mg in clause.iter() {
                    if mg.is_empty() {
                        trace!(matches = false, "empty clause");
                        continue;
                    }
                    // We need ALL of these to match. Within each type, ANY must match
                    let mut m = true;
                    m &= Self::matches_internal(
                        "destination_ip",
                        &mg.destination_ips,
                        &mg.not_destination_ips,
                        |i| i.contains(&conn.dst.ip()),
                    );
                    m &= Self::matches_internal(
                        "source_ips",
                        &mg.source_ips,
                        &mg.not_source_ips,
                        |i| i.contains(&conn.src.ip()),
                    );
                    m &= Self::matches_internal(
                        "destination_ports",
                        &mg.destination_ports,
                        &mg.not_destination_ports,
                        |p| *p == conn.dst.port(),
                    );
                    m &= Self::matches_internal(
                        "service_accounts",
                        &mg.service_accounts,
                        &mg.not_service_accounts,
                        |p| p.matches(&full_identity),
                    );
                    m &= Self::matches_internal(
                        "principals",
                        &mg.principals,
                        &mg.not_principals,
                        |p| p.matches_principal(&id),
                    );
                    m &= Self::matches_internal(
                        "namespaces",
                        &mg.namespaces,
                        &mg.not_namespaces,
                        |p| p.matches(&ns),
                    );

                    if m {
                        clause_match = true;
                        break;
                    }
                }

                if clause.is_empty() {
                    clause_match = true;
                    trace!(matches = clause_match, "empty clause");
                } else {
                    trace!(matches = clause_match, "clause");
                }
                rule_match &= clause_match;
                if !rule_match {
                    // Short circuit
                    break;
                }
            }
            trace!(matches = rule_match, "rule");
            if rule_match {
                return true;
            }
        }
        false
    }

    #[instrument(name= "match", level = "trace", skip_all, fields(%desc))]
    fn matches_internal<T: fmt::Debug>(
        desc: &'static str,
        positive: &Vec<T>,
        negative: &Vec<T>,
        mut predicate: impl FnMut(&T) -> bool,
    ) -> bool {
        let pm = if positive.is_empty() {
            trace!(matches = true, "type" = "positive", "no match declared");
            true
        } else {
            let matches = positive.iter().any(&mut predicate);
            trace!(%matches, "type"="positive", "{positive:?}");
            matches
        };
        let nm = if negative.is_empty() {
            trace!(matches = true, "type" = "negative", "no match declared");
            true
        } else {
            let matches = !negative.iter().any(&mut predicate);
            trace!(%matches, "type"="negative", "{negative:?}");
            matches
        };
        pm && nm
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RbacMatch {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub namespaces: Vec<StringMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_namespaces: Vec<StringMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service_accounts: Vec<ServiceAccountMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_service_accounts: Vec<ServiceAccountMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub principals: Vec<StringMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_principals: Vec<StringMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub source_ips: Vec<IpNet>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_source_ips: Vec<IpNet>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub destination_ips: Vec<IpNet>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_destination_ips: Vec<IpNet>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub destination_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_destination_ports: Vec<u16>,
}

impl RbacMatch {
    fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
            && self.not_namespaces.is_empty()
            && self.service_accounts.is_empty()
            && self.not_service_accounts.is_empty()
            && self.principals.is_empty()
            && self.not_principals.is_empty()
            && self.source_ips.is_empty()
            && self.not_source_ips.is_empty()
            && self.destination_ips.is_empty()
            && self.not_destination_ips.is_empty()
            && self.destination_ports.is_empty()
            && self.not_destination_ports.is_empty()
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum StringMatch {
    Prefix(Strng),
    Suffix(Strng),
    Exact(Strng),
    Presence(),
}

impl StringMatch {
    pub fn matches_principal(&self, check: &Strng) -> bool {
        // Istio matches all assumes spiffe:// prefix. This includes prefix matches.
        // A prefix match for "*foo" means "spiffe://*foo".
        // So we strip it, and fail if it isn't present.
        let Some(check) = check.strip_prefix("spiffe://") else {
            return false;
        };
        self.matches(check)
    }

    pub fn matches(&self, check: &str) -> bool {
        match self {
            StringMatch::Prefix(pre) => check.starts_with(pre.as_str()),
            StringMatch::Suffix(suf) => check.ends_with(suf.as_str()),
            StringMatch::Exact(exact) => exact.as_str() == check,
            StringMatch::Presence() => !check.is_empty(),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountMatch {
    namespace: Strng,
    service_account: Strng,
}

impl ServiceAccountMatch {
    pub fn matches(&self, check: &Option<&Identity>) -> bool {
        match check {
            Some(Identity::Spiffe {
                trust_domain: _,
                namespace,
                service_account,
            }) => namespace == &self.namespace && service_account == &self.service_account,
            // No identity at all, this does not match
            None => false,
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RbacScope {
    Global,
    Namespace,
    WorkloadSelector,
}

impl From<xds::istio::security::Scope> for RbacScope {
    fn from(value: xds::istio::security::Scope) -> Self {
        match value {
            xds::istio::security::Scope::WorkloadSelector => RbacScope::WorkloadSelector,
            xds::istio::security::Scope::Namespace => RbacScope::Namespace,
            xds::istio::security::Scope::Global => RbacScope::Global,
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RbacAction {
    Allow,
    Deny,
}

impl From<xds::istio::security::Action> for RbacAction {
    fn from(value: xds::istio::security::Action) -> Self {
        match value {
            xds::istio::security::Action::Allow => RbacAction::Allow,
            xds::istio::security::Action::Deny => RbacAction::Deny,
        }
    }
}

impl TryFrom<XdsRbac> for Authorization {
    type Error = WorkloadError;

    fn try_from(resource: XdsRbac) -> Result<Self, Self::Error> {
        let rules = resource
            .rules
            .into_iter()
            .map(|r| {
                r.clauses
                    .into_iter()
                    .map(|c| {
                        c.matches
                            .into_iter()
                            .map(|m| TryInto::<RbacMatch>::try_into(&m))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Authorization {
            name: strng::new(&resource.name),
            namespace: strng::new(&resource.namespace),
            scope: RbacScope::from(xds::istio::security::Scope::try_from(resource.scope)?),
            action: RbacAction::from(xds::istio::security::Action::try_from(resource.action)?),
            rules,
            dry_run: resource.dry_run,
        })
    }
}

impl TryFrom<&Match> for RbacMatch {
    type Error = WorkloadError;

    fn try_from(resource: &Match) -> Result<Self, Self::Error> {
        Ok(RbacMatch {
            namespaces: resource.namespaces.iter().filter_map(From::from).collect(),
            not_namespaces: resource
                .not_namespaces
                .iter()
                .filter_map(From::from)
                .collect(),
            service_accounts: resource.service_accounts.iter().map(From::from).collect(),
            not_service_accounts: resource
                .not_service_accounts
                .iter()
                .map(From::from)
                .collect(),
            principals: resource.principals.iter().filter_map(From::from).collect(),
            not_principals: resource
                .not_principals
                .iter()
                .filter_map(From::from)
                .collect(),
            source_ips: resource
                .source_ips
                .iter()
                .filter_map(|a| a.try_into().ok())
                .collect(),
            not_source_ips: resource
                .not_source_ips
                .iter()
                .filter_map(|a| a.try_into().ok())
                .collect(),
            destination_ips: resource
                .destination_ips
                .iter()
                .filter_map(|a| a.try_into().ok())
                .collect(),
            not_destination_ips: resource
                .not_destination_ips
                .iter()
                .filter_map(|a| a.try_into().ok())
                .collect(),
            destination_ports: resource
                .destination_ports
                .iter()
                .map(|p| *p as u16)
                .collect(),
            not_destination_ports: resource
                .not_destination_ports
                .iter()
                .map(|p| *p as u16)
                .collect(),
        })
    }
}

impl TryFrom<&XdsAddress> for IpNet {
    type Error = WorkloadError;
    fn try_from(resource: &XdsAddress) -> Result<Self, Self::Error> {
        Ok(IpNet::new(
            byte_to_ip(&resource.address)?,
            resource.length as u8,
        )?)
    }
}

impl From<&XdsStringMatch> for Option<StringMatch> {
    fn from(resource: &XdsStringMatch) -> Self {
        resource.match_type.as_ref().map(|m| match m {
            MatchType::Exact(s) => StringMatch::Exact(s.into()),
            MatchType::Prefix(s) => StringMatch::Prefix(s.into()),
            MatchType::Suffix(s) => StringMatch::Suffix(s.into()),
            MatchType::Presence(_) => StringMatch::Presence(),
        })
    }
}

impl From<&XdsServiceAccountMatch> for ServiceAccountMatch {
    fn from(resource: &XdsServiceAccountMatch) -> Self {
        Self {
            namespace: resource.namespace.as_str().into(),
            service_account: resource.service_account.as_str().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    macro_rules! rbac_test{
        ($name:ident, $m:expr, $($con:expr => $res:expr),*) => {
            rbac_test!($name, $name, $m, $($con => $res),*);
        };
        ($test_name:ident, $name:ident, $m:expr, $($con:expr => $res:expr),*) => {
            #[test]
            fn $test_name() {
                let m = RbacMatch {
                    $name: $m,
                    ..Default::default()
                };
                let pol = allow_policy(stringify!($name), vec![vec![vec![m]]]);
                $(
                    assert_eq!(pol.matches($con), $res, "{}", $con);
                )*
            }
        };
    }

    fn allow_policy(name: &str, rules: Vec<Vec<Vec<RbacMatch>>>) -> Authorization {
        Authorization {
            name: name.into(),
            namespace: "namespace".into(),
            scope: RbacScope::Global,
            action: RbacAction::Allow,
            rules,
            dry_run: false,
        }
    }

    fn plaintext_conn() -> Connection {
        Connection {
            src_identity: None,
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:8080".parse().unwrap(),
        }
    }

    fn tls_conn() -> Connection {
        Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "namespace".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:8080".parse().unwrap(),
        }
    }

    fn tls_conn_alt() -> Connection {
        Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td-alt".into(),
                namespace: "ns-alt".into(),
                service_account: "sa=alt".into(),
            }),
            src: "127.0.0.3:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.4:9090".parse().unwrap(),
        }
    }

    #[test]
    fn rbac_empty_policy() {
        assert!(
            !allow_policy(
                "empty",
                vec![vec![vec![RbacMatch {
                    ..Default::default()
                }]]]
            )
            .matches(&plaintext_conn())
        );
        assert!(allow_policy("empty", vec![vec![vec![]]]).matches(&plaintext_conn()));
        assert!(allow_policy("empty", vec![vec![]]).matches(&plaintext_conn()));
        assert!(!allow_policy("empty", vec![]).matches(&plaintext_conn()));
    }

    #[test]
    fn rbac_nesting() {
        let pol = allow_policy(
            "nested",
            vec![vec![
                vec![
                    RbacMatch {
                        namespaces: vec![StringMatch::Exact("a".into())],
                        ..Default::default()
                    },
                    RbacMatch {
                        namespaces: vec![StringMatch::Exact("b".into())],
                        ..Default::default()
                    },
                ],
                vec![RbacMatch {
                    destination_ports: vec![80],
                    ..Default::default()
                }],
            ]],
        );
        // Can match either namespace...
        assert!(pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "a".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
        assert!(pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "b".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
        // Policy is applied regardless of network
        assert!(pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "b".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "remote".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
        // Wrong namespace
        assert!(!pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "bad".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
        // Wrong port
        assert!(!pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "b".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:12345".parse().unwrap(),
        }));
    }

    #[test]
    fn rbac_multi_rule() {
        let pol = allow_policy(
            "nested",
            vec![
                vec![vec![RbacMatch {
                    namespaces: vec![StringMatch::Exact("a".into())],
                    ..Default::default()
                }]],
                vec![vec![RbacMatch {
                    namespaces: vec![StringMatch::Exact("b".into())],
                    ..Default::default()
                }]],
            ],
        );
        // Can match either namespace...
        assert!(pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "a".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
        assert!(pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "b".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
        // Wrong namespace
        assert!(!pol.matches(&Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "bad".into(),
                service_account: "account".into(),
            }),
            src: "127.0.0.1:1234".parse().unwrap(),
            dst_network: "".into(),
            dst: "127.0.0.2:80".parse().unwrap(),
        }));
    }

    rbac_test!(namespaces, vec![StringMatch::Exact("namespace".into())],
        &plaintext_conn() => false,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_namespaces, vec![StringMatch::Exact("namespace".into())],
        &plaintext_conn() => true,
        &tls_conn() => false,
        &tls_conn_alt() => true);

    rbac_test!(service_accounts, vec![ServiceAccountMatch {namespace: "namespace".into(), service_account: "account".into() }],
        &plaintext_conn() => false,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_service_accounts, vec![ServiceAccountMatch {namespace: "namespace".into(), service_account: "account".into() }],
        &plaintext_conn() => true,
        &tls_conn() => false,
        &tls_conn_alt() => true);

    rbac_test!(principals, vec![StringMatch::Exact("td/ns/namespace/sa/account".into())],
        &plaintext_conn() => false,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_principals, vec![StringMatch::Exact("td/ns/namespace/sa/account".into())],
        &plaintext_conn() => true,
        &tls_conn() => false,
        &tls_conn_alt() => true);

    rbac_test!(source_ips, vec![IpNet::new("127.0.0.1".parse().unwrap(), 32).unwrap()],
        &plaintext_conn() => true,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_source_ips, vec![IpNet::new("127.0.0.1".parse().unwrap(), 32).unwrap()],
        &plaintext_conn() => false,
        &tls_conn() => false,
        &tls_conn_alt() => true);

    rbac_test!(destination_ips, vec![IpNet::new("127.0.0.2".parse().unwrap(), 32).unwrap()],
        &plaintext_conn() => true,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_destination_ips, vec![IpNet::new("127.0.0.2".parse().unwrap(), 32).unwrap()],
        &plaintext_conn() => false,
        &tls_conn() => false,
        &tls_conn_alt() => true);
    rbac_test!(cidr_range, destination_ips, vec![IpNet::new("127.0.0.1".parse().unwrap(), 24).unwrap()],
        &plaintext_conn() => true,
        &tls_conn() => true,
        &tls_conn_alt() => true);

    rbac_test!(destination_ports, vec![8080],
        &plaintext_conn() => true,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_destination_ports, vec![8080],
        &plaintext_conn() => false,
        &tls_conn() => false,
        &tls_conn_alt() => true);

    #[test_case(StringMatch::Exact("foo".into()), "foo", true; "exact match")]
    #[test_case(StringMatch::Exact("foo".into()), "not", false; "exact mismatch")]
    #[test_case(StringMatch::Exact("foo".into()), "", false; "exact empty mismatch")]
    #[test_case(StringMatch::Prefix("foo".into()), "foobar", true; "prefix match")]
    #[test_case(StringMatch::Prefix("foo".into()), "notfoo", false; "prefix mismatch")]
    #[test_case(StringMatch::Prefix("foo".into()), "", false; "prefix empty mismatch")]
    #[test_case(StringMatch::Suffix("foo".into()), "barfoo", true; "suffix match")]
    #[test_case(StringMatch::Suffix("foo".into()), "foonot", false; "suffix mismatch")]
    #[test_case(StringMatch::Suffix("foo".into()), "", false; "suffix empty mismatch")]
    #[test_case(StringMatch::Presence(), "foo", true; "presence match")]
    #[test_case(StringMatch::Presence(), "", false; "presence mismatch")]
    fn string_match(matcher: StringMatch, matchee: &str, expect: bool) {
        assert_eq!(matcher.matches(matchee), expect)
    }
}
