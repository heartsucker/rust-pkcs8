#!/bin/bash
set -eux

cd "$(dirname "$0")"

for key_size in 2048 4096; do
    key="rsa-$key_size"
    pk8="$key.pk8.der"
    pk8_enc="$key-encrypted.pk8.der"
    pk8_scrypt="$key-scrypt-encrypted.pk8.der"
    key="$key.der"

    if [ ! -f "$key" ]; then
        openssl genpkey -algorithm RSA \
                        -pkeyopt "rsa_keygen_bits:$key_size" \
                        -pkeyopt rsa_keygen_pubexp:65537 \
                        -outform der \
                        -out "$key"
    fi

    openssl pkcs8 -topk8 \
                  -inform der \
                  -in "$key" \
                  -outform der \
                  -out "$pk8" \
                  -nocrypt

    openssl pkcs8 -topk8 \
                  -inform der \
                  -in "$key" \
                  -outform der \
                  -out "$pk8_enc" \
                  -passout pass:hunter2

    openssl pkcs8 -topk8 \
                  -inform der \
                  -in "$key" \
                  -outform der \
                  -out "$pk8_scrypt" \
                  -scrypt \
                  -passout pass:hunter2
done
