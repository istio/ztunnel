#!/bin/bash

# Specifically using RSA as this makes the signing deterministic, which is
# useful for tests.

if [ ! -f ca-key.pem ]; then
    # Only gen if doesn't exist. As some tests depend on the existing content of root cert.
    openssl genrsa -f4 -out ca-key.pem
    openssl req -x509 -new -nodes -key "ca-key.pem" -days 100000 -out "root-cert.pem" -subj "/O=cluster.local"
fi

openssl req -x509 -new -nodes -CA "root-cert.pem" -CAkey "ca-key.pem" -newkey rsa:2048 -keyout "intermediary-key.pem" -days 100000 -out "intermediary-cert.pem" -subj "/O=intermediary.cluster.local"
openssl req -x509 -new -nodes -CA "intermediary-cert.pem" -CAkey "intermediary-key.pem" -newkey rsa:2048 -keyout "istiod-key.pem" -days 100000 -out "istiod-cert.pem" -subj "/O=istiod.cluster.local"


if [ ! -f key.pem ]; then
    # Only gen if doesn't exist. As some tests depend on the existing content of the key.
    openssl ecparam -name prime256v1 -genkey -noout -out key.pem
    # Convert to more compatible format
    openssl pkcs8 -topk8 -in key.pem -out key.pem -nocrypt
fi

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
openssl x509 -req -in "client.csr" -CA "istiod-cert.pem" -CAkey "istiod-key.pem" -CAcreateserial -out "cert.pem" -days 100000 -extensions v3_req -extfile "client.conf"
rm client.conf client.csr istiod-cert.srl

# technically root-cert.pem shouldn't be included here, but sometimes users do it anyway.
cat istiod-cert.pem intermediary-cert.pem root-cert.pem > cert-chain.pem
