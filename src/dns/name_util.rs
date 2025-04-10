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

use hickory_proto::rr::Name;

/// Returns true if the given name ends with the labels provided by the domain iterator.
// TODO(nmittler): Consider upstreaming to TrustDNS.
pub fn has_domain(name: &Name, domain: &Name) -> bool {
    if domain.is_wildcard() || name.num_labels() <= domain.num_labels() {
        return false;
    }

    let name_iter = name.iter();
    let domain_iter = domain.iter();

    // Skip ahead to the start of the domain.
    let num_skip = name_iter.len() - domain_iter.len();
    let name_iter = name_iter.skip(num_skip);

    // Compare the remaining elements.
    name_iter.eq(domain_iter)
}

/// Trims the domain labels from the name. Returns `Some` if the domain was found and removed.
// TODO(nmittler): Consider upstreaming to TrustDNS.
pub fn trim_domain(name: &Name, domain: &Name) -> Option<Name> {
    if has_domain(name, domain) {
        // Create a Name from the labels leading up to the domain.
        let iter = name.iter();
        let num_labels = iter.len() - domain.num_labels() as usize;
        let mut name = Name::from_labels(iter.take(num_labels)).unwrap();
        name.set_fqdn(false);
        Some(name)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::dns::n;
    use hickory_proto::rr::Name;

    #[test]
    fn test_has_domain() {
        assert!(has_domain(&n("name.ns.svc.cluster.local"), &domain()));

        assert!(!has_domain(&n("name.ns.a.different.domain"), &domain()));

        assert!(!has_domain(&n("cluster.com"), &domain()));
    }

    #[test]
    fn test_trim_domain() {
        assert_eq!(
            Some(n("name.ns")),
            trim_domain(&n("name.ns.svc.cluster.local"), &domain())
        );

        assert_eq!(
            None,
            trim_domain(&n("name.ns.a.different.domain"), &domain())
        );

        // Can't trim if nothing left.
        assert_eq!(None, trim_domain(&n("svc.cluster.local"), &domain()));
    }

    fn domain() -> Name {
        n("svc.cluster.local")
    }
}
