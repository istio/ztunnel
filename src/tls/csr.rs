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

use crate::tls::Error;

pub struct CertSign {
    pub csr: String,
    pub private_key: Vec<u8>,
}

pub struct CsrOptions {
    pub san: String,
}

impl CsrOptions {
    #[cfg(feature = "tls-boring")]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use boring::ec::{EcGroup, EcKey};
        use boring::hash::MessageDigest;
        use boring::nid::Nid;
        use boring::pkey::PKey;
        use boring::stack::Stack;
        use boring::x509::extension::SubjectAlternativeName;
        use boring::x509::{self};
        // TODO: https://github.com/rustls/rcgen/issues/228 can we always use rcgen?

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        let mut csr = x509::X509ReqBuilder::new()?;
        csr.set_pubkey(&pkey)?;
        let mut extensions = Stack::new()?;
        let subject_alternative_name = SubjectAlternativeName::new()
            .uri(&self.san)
            .critical()
            .build(&csr.x509v3_context(None))?;

        extensions.push(subject_alternative_name)?;
        csr.add_extensions(&extensions)?;
        csr.sign(&pkey, MessageDigest::sha256())?;

        let csr = csr.build();
        let pkey_pem = pkey.private_key_to_pem_pkcs8()?;
        let csr_pem = csr.to_pem()?;
        let csr_pem = std::str::from_utf8(&csr_pem)
            .expect("CSR is valid string")
            .to_string();
        Ok(CertSign {
            csr: csr_pem,
            private_key: pkey_pem,
        })
    }

    #[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use rcgen::{CertificateParams, DistinguishedName, SanType};
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let private_key = kp.serialize_pem();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(self.san.clone().try_into()?)];
        params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        // Avoid setting CN. rcgen defaults it to "rcgen self signed cert" which we don't want
        params.distinguished_name = DistinguishedName::new();
        let csr = params.serialize_request(&kp)?.pem()?;

        Ok(CertSign {
            csr,
            private_key: private_key.into(),
        })
    }

    #[cfg(feature = "tls-openssl")]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::stack::Stack;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{self};
        // TODO: https://github.com/rustls/rcgen/issues/228 can we always use rcgen?

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        let mut csr = x509::X509ReqBuilder::new()?;
        csr.set_pubkey(&pkey)?;
        let mut extensions = Stack::new()?;
        let subject_alternative_name = SubjectAlternativeName::new()
            .uri(&self.san)
            .critical()
            .build(&csr.x509v3_context(None))?;

        extensions.push(subject_alternative_name)?;
        csr.add_extensions(&extensions)?;
        csr.sign(&pkey, MessageDigest::sha256())?;

        let csr = csr.build();
        let pkey_pem = pkey.private_key_to_pem_pkcs8()?;
        let csr_pem = csr.to_pem()?;
        let csr_pem = std::str::from_utf8(&csr_pem)
            .expect("CSR is valid string")
            .to_string();
        Ok(CertSign {
            csr: csr_pem,
            private_key: pkey_pem,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::tls;

    #[test]
    fn test_csr() {
        use x509_parser::prelude::FromDer;
        let csr = tls::csr::CsrOptions {
            san: "spiffe://td/ns/ns1/sa/sa1".to_string(),
        }
        .generate()
        .unwrap();
        let (_, der) = x509_parser::pem::parse_x509_pem(csr.csr.as_bytes()).unwrap();

        let (_, cert) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der.contents)
                .unwrap();
        cert.verify_signature().unwrap();
        let attr = cert
            .certification_request_info
            .iter_attributes()
            .next()
            .unwrap();
        // SAN is encoded in some format I don't understand how to parse; this could be improved.
        // but make sure it's there in a hacky manner
        assert!(attr.value.ends_with(b"spiffe://td/ns/ns1/sa/sa1"));
    }
}
