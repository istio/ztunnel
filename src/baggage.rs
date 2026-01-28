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

use crate::strng::Strng;
use hyper::{
    header::{GetAll, ToStrError},
    http::HeaderValue,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Baggage {
    pub cluster_id: Option<Strng>,
    pub namespace: Option<Strng>,
    pub workload_name: Option<Strng>,
    pub service_name: Option<Strng>,
    pub revision: Option<Strng>,
    pub region: Option<Strng>,
    pub zone: Option<Strng>,
}

pub fn baggage_header_val(baggage: &Baggage, workload_type: &str) -> String {
    [
        baggage
            .cluster_id
            .as_ref()
            .map(|cluster| format!("k8s.cluster.name={cluster}")),
        baggage
            .namespace
            .as_ref()
            .map(|namespace| format!("k8s.namespace.name={namespace}")),
        baggage
            .workload_name
            .as_ref()
            .map(|workload| format!("k8s.{workload_type}.name={workload}")),
        baggage
            .service_name
            .as_ref()
            .map(|service| format!("service.name={service}")),
        baggage
            .revision
            .as_ref()
            .map(|revision| format!("service.version={revision}")),
        baggage
            .region
            .as_ref()
            .map(|region| format!("cloud.region={region}")),
        baggage
            .zone
            .as_ref()
            .map(|zone| format!("cloud.availability_zone={zone}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(",")
}

pub fn parse_baggage_header(headers: GetAll<HeaderValue>) -> Result<Baggage, ToStrError> {
    let mut baggage = Baggage {
        ..Default::default()
    };
    for hv in headers.iter() {
        let v = hv.to_str()?;
        v.split(',').for_each(|s| {
            let parts: Vec<&str> = s.split('=').collect();
            if parts.len() > 1 {
                let val = match parts[1] {
                    "" => None,
                    s => Some(s.into()),
                };
                match parts[0] {
                    "k8s.cluster.name" => baggage.cluster_id = val,
                    "k8s.namespace.name" => baggage.namespace = val,
                    "k8s.deployment.name"
                    | "k8s.cronjob.name"
                    | "k8s.pod.name"
                    | "k8s.job.name" => baggage.workload_name = val,
                    "service.name" => baggage.service_name = val,
                    "service.version" => baggage.revision = val,
                    // https://opentelemetry.io/docs/specs/semconv/attributes-registry/cloud/
                    "cloud.region" => baggage.region = val,
                    "cloud.availability_zone" => baggage.zone = val,
                    _ => {}
                }
            }
        });
    }
    Ok(baggage)
}

#[cfg(test)]
pub mod tests {
    use hyper::{HeaderMap, http::HeaderValue};

    use crate::proxy::BAGGAGE_HEADER;
    use crate::strng::Strng;

    use super::{Baggage, baggage_header_val, parse_baggage_header};

    #[test]
    fn baggage_parser() -> anyhow::Result<()> {
        let mut hm = HeaderMap::new();
        let baggage_str = "k8s.cluster.name=K1,k8s.namespace.name=NS1,k8s.deployment.name=N1,service.name=N2,service.version=V1";
        let header_value = HeaderValue::from_str(baggage_str)?;
        hm.append(BAGGAGE_HEADER, header_value);
        let baggage = parse_baggage_header(hm.get_all(BAGGAGE_HEADER))?;
        assert_eq!(baggage.cluster_id, Some("K1".into()));
        assert_eq!(baggage.namespace, Some("NS1".into()));
        assert_eq!(baggage.workload_name, Some("N1".into()));
        assert_eq!(baggage.service_name, Some("N2".into()));
        assert_eq!(baggage.revision, Some("V1".into()));
        Ok(())
    }

    #[test]
    fn baggage_parser_empty_values() -> anyhow::Result<()> {
        let mut hm = HeaderMap::new();
        let baggage_str = "k8s.cluster.name=,k8s.namespace.name=,k8s.deployment.name=,service.name=,service.version=";
        let header_value = HeaderValue::from_str(baggage_str)?;
        hm.append(BAGGAGE_HEADER, header_value);
        let baggage = parse_baggage_header(hm.get_all(BAGGAGE_HEADER))?;
        assert_eq!(baggage.cluster_id, None);
        assert_eq!(baggage.namespace, None);
        assert_eq!(baggage.workload_name, None);
        assert_eq!(baggage.service_name, None);
        assert_eq!(baggage.revision, None);
        Ok(())
    }

    #[test]
    fn baggage_parser_multiline() -> anyhow::Result<()> {
        let mut hm = HeaderMap::new();
        hm.append(
            BAGGAGE_HEADER,
            HeaderValue::from_str("k8s.cluster.name=K1")?,
        );
        hm.append(
            BAGGAGE_HEADER,
            HeaderValue::from_str("k8s.namespace.name=NS1")?,
        );
        hm.append(
            BAGGAGE_HEADER,
            HeaderValue::from_str("k8s.deployment.name=N1")?,
        );
        hm.append(BAGGAGE_HEADER, HeaderValue::from_str("service.name=N2")?);
        hm.append(BAGGAGE_HEADER, HeaderValue::from_str("service.version=V1")?);
        let baggage = parse_baggage_header(hm.get_all(BAGGAGE_HEADER))?;
        assert_eq!(baggage.cluster_id, Some("K1".into()));
        assert_eq!(baggage.namespace, Some("NS1".into()));
        assert_eq!(baggage.workload_name, Some("N1".into()));
        assert_eq!(baggage.service_name, Some("N2".into()));
        assert_eq!(baggage.revision, Some("V1".into()));
        Ok(())
    }

    #[test]
    fn baggage_parser_no_header() -> anyhow::Result<()> {
        let baggage = parse_baggage_header(HeaderMap::new().get_all(BAGGAGE_HEADER))?;
        assert_eq!(baggage.cluster_id, None);
        assert_eq!(baggage.namespace, None);
        assert_eq!(baggage.workload_name, None);
        assert_eq!(baggage.service_name, None);
        assert_eq!(baggage.revision, None);
        Ok(())
    }

    #[test]
    fn baggage_header_val_can_be_parsed() -> anyhow::Result<()> {
        {
            let baggage = Baggage {
                ..Default::default()
            };
            let mut hm = HeaderMap::new();
            hm.append(
                BAGGAGE_HEADER,
                HeaderValue::from_str(&baggage_header_val(&baggage, "deployment"))?,
            );
            let parsed = parse_baggage_header(hm.get_all(BAGGAGE_HEADER))?;
            assert_eq!(baggage, parsed);
        }
        {
            let baggage = Baggage {
                cluster_id: Some(Strng::from("cluster")),
                namespace: Some(Strng::from("default")),
                workload_name: Some(Strng::from("workload")),
                service_name: Some(Strng::from("service")),
                ..Default::default()
            };
            let mut hm = HeaderMap::new();
            hm.append(
                BAGGAGE_HEADER,
                HeaderValue::from_str(&baggage_header_val(&baggage, "deployment"))?,
            );
            let parsed = parse_baggage_header(hm.get_all(BAGGAGE_HEADER))?;
            assert_eq!(baggage, parsed);
        }
        Ok(())
    }
}
