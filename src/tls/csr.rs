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

    #[cfg(feature = "tls-ring")]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use rcgen::{Certificate, CertificateParams, SanType};
        let kp = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("TODO");
        let private_key = kp.serialize_pem();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(self.san.clone())];
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        params.key_pair = Some(kp);
        let cert = Certificate::from_params(params).expect("TODO");
        let csr = cert.serialize_request_pem().expect("TODO");

        Ok(CertSign {
            csr,
            private_key: private_key.into(),
        })
    }
}
