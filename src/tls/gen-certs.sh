#!/bin/bash

# Specifically using RSA as this makes the signing deterministic, which is
# useful for tests.
openssl genrsa -f4 -out ca-key.pem
openssl req -x509 -new -nodes -key "ca-key.pem" -days 100000 -out "root-cert.pem" -subj "/O=cluster.local"

openssl ecparam -name prime256v1 -genkey -noout -out key.pem
cat > "client.conf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @alt_names
[alt_names]
URI = spiffe://cluster.local/ns/default/sa/default
EOF
openssl req -new -sha256 -key "key.pem" -out "client.csr" -subj "/CN=default.default.svc.cluster.local" -config "client.conf"
openssl x509 -req -in "client.csr" -CA "root-cert.pem" -CAkey "ca-key.pem" -CAcreateserial -out "cert-chain.pem" -days 100000 -extensions v3_req -extfile "client.conf"
rm client.conf client.csr root-cert.srl
