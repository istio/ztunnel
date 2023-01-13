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

use std::convert::Into;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use tracing::{instrument, trace};

use xds::istio::security::Address as XdsAddress;
use xds::istio::security::Authorization as XdsRbac;
use xds::istio::security::StringMatch as XdsStringMatch;

use crate::identity::Identity;
use crate::workload::WorkloadError;
use crate::workload::WorkloadError::EnumParse;
use crate::{workload, xds};
use xds::istio::security::string_match::MatchType;
use xds::istio::security::Match;

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    pub name: String,
    pub namespace: String,
    pub scope: RbacScope,
    pub action: RbacAction,
    pub groups: Vec<Vec<Vec<RbacMatch>>>,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub src_identity: Option<Identity>,
    pub src_ip: IpAddr,
    pub dst: SocketAddr,
}

struct OptionDisplay<'a, T>(&'a Option<T>);

impl<'a, T: Display> Display for OptionDisplay<'a, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => write!(f, "None"),
            Some(i) => write!(f, "{}", i),
        }
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})->{}",
            self.src_ip,
            OptionDisplay(&self.src_identity),
            self.dst
        )
    }
}

impl Authorization {
    pub fn to_key(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }

    #[instrument(level = "trace", skip_all, fields(policy=self.to_key()))]
    pub fn matches(&self, conn: &Connection) -> bool {
        let id = conn
            .src_identity
            .as_ref()
            .map(|i| i.to_string())
            .unwrap_or_default();
        let ns = conn
            .src_identity
            .as_ref()
            .map(|i| match i {
                Identity::Spiffe { namespace, .. } => namespace.clone(),
            })
            .unwrap_or_default();
        if self.groups.is_empty() {
            trace!(matches = false, "empty groups");
            return false;
        }
        for rule in self.groups.iter() {
            // If ANY rule matches, it is a match...
            let mut rule_match = true;
            for group in rule.iter() {
                // We need ALL groups to match...
                let mut group_match = true;
                for mg in group.iter() {
                    if mg.is_empty() {
                        trace!(matches = false, "empty rule");
                        group_match = false;
                        break;
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
                        |i| i.contains(&conn.src_ip),
                    );
                    m &= Self::matches_internal(
                        "destination_ports",
                        &mg.destination_ports,
                        &mg.not_destination_ports,
                        |p| *p == conn.dst.port(),
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

                    group_match &= m;
                }

                if group.is_empty() {
                    trace!(matches = true, "empty group");
                } else {
                    trace!(matches = group_match, "group");
                }
                rule_match &= group_match;
            }
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
pub struct RbacMatch {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub namespaces: Vec<StringMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_namespaces: Vec<StringMatch>,
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
    Prefix(String),
    Suffix(String),
    Exact(String),
    Presence(),
}

impl StringMatch {
    pub fn matches_principal(&self, check: &str) -> bool {
        // Istio matches all assumes spiffe:// prefix. This includes prefix matches.
        // A prefix match for "*foo" means "spiffe://*foo".
        // So we strip it, and fail if it isn't present.
        let Some(check) = check.strip_prefix("spiffe://") else {
            return false
        };
        self.matches(check)
    }

    pub fn matches(&self, check: &str) -> bool {
        match self {
            StringMatch::Prefix(pre) => check.starts_with(pre),
            StringMatch::Suffix(suf) => check.ends_with(suf),
            StringMatch::Exact(exact) => exact == check,
            StringMatch::Presence() => !check.is_empty(),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RbacScope {
    Global,
    Namespace,
    WorkloadSelector,
}

impl TryFrom<Option<xds::istio::security::Scope>> for RbacScope {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::security::Scope>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::security::Scope::WorkloadSelector) => Ok(RbacScope::WorkloadSelector),
            Some(xds::istio::security::Scope::Namespace) => Ok(RbacScope::Namespace),
            Some(xds::istio::security::Scope::Global) => Ok(RbacScope::Global),
            None => Err(EnumParse("unknown type".into())),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RbacAction {
    Allow,
    Deny,
}

impl TryFrom<Option<xds::istio::security::Action>> for RbacAction {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::security::Action>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::security::Action::Allow) => Ok(RbacAction::Allow),
            Some(xds::istio::security::Action::Deny) => Ok(RbacAction::Deny),
            None => Err(EnumParse("unknown type".into())),
        }
    }
}

impl TryFrom<&XdsRbac> for Authorization {
    type Error = WorkloadError;

    fn try_from(resource: &XdsRbac) -> Result<Self, Self::Error> {
        let resource: XdsRbac = resource.to_owned();
        let groups = resource
            .groups
            .into_iter()
            .map(|g| {
                g.rules
                    .into_iter()
                    .map(|r| {
                        r.matches
                            .into_iter()
                            .map(|m| TryInto::<RbacMatch>::try_into(&m))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Authorization {
            name: resource.name,
            namespace: resource.namespace,
            scope: RbacScope::try_from(xds::istio::security::Scope::from_i32(resource.scope))?,
            action: RbacAction::try_from(xds::istio::security::Action::from_i32(resource.action))?,
            groups,
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
            workload::byte_to_ip(&resource.address)?,
            resource.length as u8,
        )?)
    }
}

impl From<&XdsStringMatch> for Option<StringMatch> {
    fn from(resource: &XdsStringMatch) -> Self {
        resource.match_type.as_ref().map(|m| match m {
            MatchType::Exact(s) => StringMatch::Exact(s.clone()),
            MatchType::Prefix(s) => StringMatch::Prefix(s.clone()),
            MatchType::Suffix(s) => StringMatch::Suffix(s.clone()),
            MatchType::Presence(_) => StringMatch::Presence(),
        })
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
                let pol = allow_policy(stringify!($name).to_string(), vec![vec![vec![m]]]);
                $(
                    assert_eq!(pol.matches($con), $res, "{}", $con);
                )*
            }
        };
    }

    fn allow_policy(name: String, group: Vec<Vec<Vec<RbacMatch>>>) -> Authorization {
        Authorization {
            name,
            namespace: "namespace".to_string(),
            scope: RbacScope::Global,
            action: RbacAction::Allow,
            groups: group,
        }
    }

    fn plaintext_conn() -> Connection {
        Connection {
            src_identity: None,
            src_ip: IpAddr::from([127, 0, 0, 1]),
            dst: "127.0.0.2:8080".parse().unwrap(),
        }
    }

    fn tls_conn() -> Connection {
        Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td".to_string(),
                namespace: "namespace".to_string(),
                service_account: "account".to_string(),
            }),
            src_ip: IpAddr::from([127, 0, 0, 1]),
            dst: "127.0.0.2:8080".parse().unwrap(),
        }
    }

    fn tls_conn_alt() -> Connection {
        Connection {
            src_identity: Some(Identity::Spiffe {
                trust_domain: "td-alt".to_string(),
                namespace: "ns-alt".to_string(),
                service_account: "sa=alt".to_string(),
            }),
            src_ip: IpAddr::from([127, 0, 0, 3]),
            dst: "127.0.0.4:9090".parse().unwrap(),
        }
    }

    #[test]
    fn rbac_empty_policy() {
        assert!(!allow_policy(
            "empty".to_string(),
            vec![vec![vec![RbacMatch {
                ..Default::default()
            }]]]
        )
        .matches(&plaintext_conn()));
        assert!(allow_policy("empty".to_string(), vec![vec![vec![]]]).matches(&plaintext_conn()));
        assert!(allow_policy("empty".to_string(), vec![vec![]]).matches(&plaintext_conn()));
        assert!(!allow_policy("empty".to_string(), vec![]).matches(&plaintext_conn()));
    }

    rbac_test!(namespaces, vec![StringMatch::Exact("namespace".to_string())],
        &plaintext_conn() => false,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_namespaces, vec![StringMatch::Exact("namespace".to_string())],
        &plaintext_conn() => true,
        &tls_conn() => false,
        &tls_conn_alt() => true);

    rbac_test!(principals, vec![StringMatch::Exact("td/ns/namespace/sa/account".to_string())],
        &plaintext_conn() => false,
        &tls_conn() => true,
        &tls_conn_alt() => false);
    rbac_test!(not_principals, vec![StringMatch::Exact("td/ns/namespace/sa/account".to_string())],
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

    #[test_case(StringMatch::Exact("foo".to_string()), "foo", true; "exact match")]
    #[test_case(StringMatch::Exact("foo".to_string()), "not", false; "exact mismatch")]
    #[test_case(StringMatch::Exact("foo".to_string()), "", false; "exact empty mismatch")]
    #[test_case(StringMatch::Prefix("foo".to_string()), "foobar", true; "prefix match")]
    #[test_case(StringMatch::Prefix("foo".to_string()), "notfoo", false; "prefix mismatch")]
    #[test_case(StringMatch::Prefix("foo".to_string()), "", false; "prefix empty mismatch")]
    #[test_case(StringMatch::Suffix("foo".to_string()), "barfoo", true; "suffix match")]
    #[test_case(StringMatch::Suffix("foo".to_string()), "foonot", false; "suffix mismatch")]
    #[test_case(StringMatch::Suffix("foo".to_string()), "", false; "suffix empty mismatch")]
    #[test_case(StringMatch::Presence(), "foo", true; "presence match")]
    #[test_case(StringMatch::Presence(), "", false; "presence mismatch")]
    fn string_match(matcher: StringMatch, matchee: &str, expect: bool) {
        assert_eq!(matcher.matches(matchee), expect)
    }
}
