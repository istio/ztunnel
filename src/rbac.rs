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

use xds::istio::workload::Address as XdsAddress;
use xds::istio::workload::Rbac as XdsRbac;
use xds::istio::workload::StringMatch as XdsStringMatch;

use crate::identity::Identity;
use crate::workload::WorkloadError;
use crate::workload::WorkloadError::EnumParse;
use crate::xds::istio::workload::string_match::MatchType;
use crate::xds::istio::workload::RbacPolicyRuleMatch;
use crate::{workload, xds};

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rbac {
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

impl Rbac {
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
                        |p| p.matches(&id),
                    );
                    m &= Self::matches_internal(
                        "namespaces",
                        &mg.namespaces,
                        &mg.not_namespaces,
                        |p| p.matches(&ns),
                    );

                    group_match &= m;
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
            let matches = negative.iter().any(&mut predicate);
            trace!(%matches, "type"="negative", "{negative:?}");
            matches
        };
        pm && nm
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
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
    pub fn matches(&self, check: &str) -> bool {
        // Istio matches all assumes spiffe:// prefix. This includes prefix matches.
        // A prefix match for "*foo" means "spiffe://*foo".
        // So we strip it, and fail if it isn't present.
        let Some(check) = check.strip_prefix("spiffe://") else {
            return false
        };
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

impl TryFrom<Option<xds::istio::workload::RbacScope>> for RbacScope {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::workload::RbacScope>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::RbacScope::WorkloadSelector) => {
                Ok(RbacScope::WorkloadSelector)
            }
            Some(xds::istio::workload::RbacScope::Namespace) => Ok(RbacScope::Namespace),
            Some(xds::istio::workload::RbacScope::Global) => Ok(RbacScope::Global),
            None => Err(EnumParse("unknown type".into())),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RbacAction {
    Allow,
    Deny,
}

impl TryFrom<Option<xds::istio::workload::RbacPolicyAction>> for RbacAction {
    type Error = WorkloadError;

    fn try_from(
        value: Option<xds::istio::workload::RbacPolicyAction>,
    ) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::RbacPolicyAction::Allow) => Ok(RbacAction::Allow),
            Some(xds::istio::workload::RbacPolicyAction::Deny) => Ok(RbacAction::Deny),
            None => Err(EnumParse("unknown type".into())),
        }
    }
}

impl TryFrom<&XdsRbac> for Rbac {
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
        Ok(Rbac {
            name: resource.name,
            namespace: resource.namespace,
            scope: RbacScope::try_from(xds::istio::workload::RbacScope::from_i32(resource.scope))?,
            action: RbacAction::try_from(xds::istio::workload::RbacPolicyAction::from_i32(
                resource.action,
            ))?,
            groups,
        })
    }
}

impl TryFrom<&RbacPolicyRuleMatch> for RbacMatch {
    type Error = WorkloadError;

    fn try_from(resource: &RbacPolicyRuleMatch) -> Result<Self, Self::Error> {
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
