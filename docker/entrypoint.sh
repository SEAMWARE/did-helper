#!/bin/bash

set -eo pipefail

KEY_TYPE_TO_GENERATE="${KEY_TYPE_TO_GENERATE:-EC}"
KEY_TYPE="${KEY_TYPE:-P-256}"
STORE_PASS="${STORE_PASS:-changeit}"

cd /cert

if [[ -z "${KEYSTORE_PATH:-}" ]] && [[ -z "${CERT_URL:-}" ]]; then
  case "$KEY_TYPE_TO_GENERATE" in
    EC)
      case "$KEY_TYPE" in
        P-256)
          echo "Generating EC P-256 key pair..."
          openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
          openssl ec -in private-key.pem -pubout -out public-key.pem
          ;;
        P-384)
          echo "Generating EC P-384 key pair..."
          openssl ecparam -name secp384r1 -genkey -noout -out private-key.pem
          openssl ec -in private-key.pem -pubout -out public-key.pem
          ;;
        *)
          echo "Unsupported EC curve: $EC_CURVE. Use P-256 or P-384."
          exit 1
          ;;
      esac
      ;;
    ED-25519)
      echo "Generating Ed25519 key pair..."
      openssl genpkey -algorithm Ed25519 -out private-key.pem
      openssl pkey -in private-key.pem -pubout -out public-key.pem
      ;;
    RSA)
      echo "Generating RSA 4096-bit key pair..."
      openssl genrsa -out private-key.pem 4096
      openssl rsa -in private-key.pem -pubout -out public-key.pem
      ;;
    *)
      echo "Unsupported KEY_TYPE: $KEY_TYPE_TO_GENERATE. Use 'EC', 'ED25519' or 'RSA'."
      exit 1
      ;;
  esac
  echo -e "Generating certificate\nC=${COUNTRY}\nST=${STATE}\nL=${LOCALITY}\nO=${ORGANIZATION}\CN=${COMMON_NAME}"

  openssl req -new -x509 -key private-key.pem -out cert.pem -days 360 \
    -subj "/C=${COUNTRY:-ES}/ST=${STATE:-NA}/L=${LOCALITY:-NA}/O=${ORGANIZATION:-NA}/CN=${COMMON_NAME:-localhost}"

  openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx \
    -name "${KEY_ALIAS:-cert}" -password "pass:${STORE_PASS}"

  CURRENT_KEYSTORE="/cert/cert.pfx"
else
  CURRENT_KEYSTORE="${KEYSTORE_PATH:-}"
fi

args=()

[[ -n "$CURRENT_KEYSTORE" ]] && args+=("-keystorePath" "$CURRENT_KEYSTORE")
# legacy support: KEYSTORE_PASS is the new env vars mapped automatically
[[ -n "$STORE_PASS" ]]       && args+=("-keystorePassword" "$STORE_PASS")

if [[ "${RUN_SERVER:-}" == "true" ]]; then
    args+=("-server=true")
    args+=("-port" "${SERVER_PORT:-8080}")
fi

cd /temp
/did-helper/did-helper "${args[@]}" "$@"