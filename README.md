# DID Helper

Small tool to generate [Decentralized Identifiers](https://www.w3.org/TR/did-1.0/), following the [did:key](https://w3c-ccg.github.io/did-key-spec/), [did:web](https://w3c-ccg.github.io/did-method-web/) or [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md) specs.

## Usage

The tool is provided as a plain executable or as container.

### Container

The container provides the capability to generate key material (either RSA or EC) if no KEYSTORE_PATH or CERT_URL is provided.

```shell
    docker run -v $(pwd)/cert:/cert quay.io/wi_stefan/did-helper
```
The mounted ```$(pwd)/cert``` volume will contain:
    * the key-material - cert.pem, cert.pfx, private-key.pem and public-key.pem
    * the outputfile, either in json or env format

The container can be configured, using the following environment-variables:

| Var | Description | Values |Default  |
|-----|-------------|---|----------|
| KEYSTORE_PATH | Path to the keystore to be read. | string |
| KEYSTORE_PASSWORD | Deprecated: Password to be used for the keystore | string | "myPassword" |
| STORE_PASS | Deprecated: Password to be used for the keystore | string | "myPassword" |
| CERT_PATH | Path to the PEM certificate | string |
| KEY_PATH | Path to the key PEM certificate | string |
| OUTPUT_FORMAT | Output format for the did result file. | "json", "env", "json_jwk" | "json" |
| OUTPUT_FILE | File to write the did, format depends on the requested format. Will not write the file if empty. | string | "/cert/did.json" |
| DID_TYPE | Type of the did to generate. | "key", "jwk", "web" or "keycloak" | "key" |
| KEY_TYPE | Type of the key provided. | "P-256", "P-384" or "ED-25519" | "P-256" |
| HOST_URL | Base URL where the DID document will be located, excluding 'did.json'. (e.g., https://example.com/alice for https://example.com/alice/did.json). Required for did:web | |
| CERT_URL | URL to retrieve the public certificate | string | `HOST_URL` + `/.well-known/tls.crt`
| RUN_SERVER | Run a server with /did.json and /.well-known/tls.crt endpoints | false
| SERVER_PORT | Server port | 8080 |
| KEYCLOAK_HOST | Base URL of the Keycloak instance used to fetch JWKS for realm-based DID documents (e.g., `https://keycloak.example.com`). Required when `DID_TYPE=keycloak`. | string | |
| KEYCLOAK_REALM | Fixed Keycloak realm. When set with `DID_TYPE=keycloak`, serves a static DID document for this realm at the path derived from `HOST_URL`, instead of the dynamic `/{realm}/did.json` pattern. | string | |
| IGNORE_TLS_VALIDATION | Disable TLS certificate validation when connecting to Keycloak. Do not use in production. | "true", "false" | "false" |
| KEY_TYPE_TO_GENERATE | Type of the key to be generated. RSA is only supported for did:jwk | "EC", "ED-25519" or "RSA" | "EC" |
| KEY_ALIAS | Alias for the key inside the keystore | string | "myAlias" |
| COUNTRY | Country to be set for the created certificate. | string | "DE" |
| STATE | State to be set for the created certificate. | string | "Saxony" |
| LOCALITY | Locality to be set for the created certificate. | string | "Dresden" |
| ORGANIZATION | Organization to be set for the created certificate. | string | "M&P Operations Inc." |
| COMMON_NAME | Common name to be set for the created certificate. | string | "www.mp-operations.org" |

### Executable

The tool can be executed via:

```shell
    wget https://github.com/wistefan/did-helper/releases/download/0.2.0/did-helper
    chmod +x did-helper
    ./did-helper -keystorePath ./example/cert.pfx -keystorePassword=password
```

In order to use the executable, the proper key-material has to be provided. In order to build a did:key, a P-256 Key has to be created:

#### Create P-256 Key and Certificate

In order to provide a [did:key or did:jwk of type P-256](https://w3c-ccg.github.io/did-method-key/#p-256), first a key and certificate needs to be created

```shell
# generate the private key - dont get confused about the curve, openssl uses the name `prime256v1` for `secp256r1`(as defined by P-256)
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# generate corresponding public key
openssl ec -in private-key.pem -pubout -out public-key.pem

# create a (self-signed) certificate
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

# export the keystore
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name the-alias

# check the contents
keytool -v -keystore cert.pfx -list -alias the-alias
```

#### Create RSA Key and Certificate

Alternatively, an RSA Key can be created. It can only be used for did:jwk:

```shell
# generate the private key
openssl genrsa -out private-key.pem 4096

# extract the corresponding public key
openssl rsa -in private-key.pem -pubout -out public-key.pem

# create certficate, signed with the key
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

# export it to a keystore
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name the-alias

# check the contents
keytool -v -keystore cert.pfx -list -alias the-alias
```



#### Config

The helper supports the following parameters:

```shell
Usage of ./did-helper:
  -certPath string
    	Path to the PEM certificate. (env CERT_PATH)
  -certUrl string
    	URL to retrieve the public certificate. Defaults to 'hostUrl' + /.well-known/tls.crt (env CERT_URL)
  -didType string
    	Type of the DID to generate. did:key and did:jwk are supported. (env DID_TYPE) (default "key")
  -hostUrl string
    	Base URL where the DID document will be located, excluding 'did.json'. (env HOST_URL)
  -keyPath string
    	Path to the key PEM certificate. (env KEY_PATH)
  -keyType string
    	Type of the DID key to be created. Supported: ED-25519, P-256, P-384. (env KEY_TYPE) (default "P-256")
  -keystorePassword string
    	Password for the keystore. (env KEYSTORE_PASSWORD)
  -keystorePath string
    	Path to the keystore to be read. (env KEYSTORE_PATH)
  -outputFile string
    	File to write the DID; will not write if empty. (env OUTPUT_FILE)
  -outputFormat string
    	Output format for the DID result file. Can be json, env or json_jwk. (env OUTPUT_FORMAT) (default "json")
  -port int
    	Server port. Default 8080. (env SERVER_PORT) (default 8080)
  -server
    	Run a server with /did.json and /.well-known/tls.crt endpoints. (env RUN_SERVER)
  -keycloakHost string
    	URL of the Keycloak instance used to construct the OIDC discovery and JWKS endpoints for the realms. (env KEYCLOAK_HOST)
  -keycloakRealm string
    	Fixed Keycloak realm. When set with didType=keycloak, serves a fixed DID document for this realm at the path derived from hostUrl. (env KEYCLOAK_REALM)
  -ignoreTlsValidation
    	Disable TLS validation when connecting to Keycloak. Do not use it in production. (env IGNORE_TLS_VALIDATION) (default false)
```

## Certificate Rotation (server mode)

When `-server` is enabled with a file-based certificate (`-certPath`/`-keyPath` or `-keystorePath`), the served `did.json` and `tls.crt` are refreshed automatically whenever the underlying file changes, without restarting the process.

This relies on filesystem events, so the mount must let the rotation actually reach the container:

* **Do not use `subPath`** to mount the Secret/ConfigMap holding the certificate. Kubernetes does not propagate updates to `subPath` mounts, so the watcher will never observe a rotation performed that way. Mount the whole volume instead. There is no reliable way for the watcher to detect this misconfiguration at runtime: a `subPath` mount is bind-mounted as a plain file, indistinguishable from a legitimately static local file (e.g. a `hostPath` mount or a self-generated key) — check your deployment's volume configuration directly rather than relying on a log message to catch it.
* If a rotation legitimately changes the key material (not just the certificate metadata), the resulting DID for `did:key`/`did:jwk` changes too. This is logged explicitly as a warning with the previous and new DID, since anything that pinned the old DID (trusted issuer lists, counterparties) will need to be updated.

## Keycloak Integration

The helper supports reading key material directly from a [Keycloak](https://www.keycloak.org/) instance. When configured with `-didType=keycloak`, the server exposes DID documents based on Keycloak realms using the following URL pattern:

```
/{realm}/did.json
```

Where `{realm}` is the **base64-encoded** name of the Keycloak realm. The helper will decode it, fetch the JWKS from the corresponding Keycloak realm and build the DID document accordingly.

### Configuration

| Parameter | Env Var | Description |
|-----------|---------|-------------|
| `-didType=keycloak` | `DID_TYPE=keycloak` | Enables Keycloak mode |
| `-keycloakHost` | `KEYCLOAK_HOST` | Base URL of the Keycloak instance (e.g., `https://keycloak.example.com`) |
| `-keycloakRealm` | `KEYCLOAK_REALM` | Fixed realm name. When set, the server exposes a single static DID document at the path derived from `-hostUrl` (e.g., `/my/path/did.json`) instead of the dynamic `/{realm}/did.json` pattern. The certificate is available at `/.well-known/tls.crt` under the same base path. |
| `-ignoreTlsValidation` | `IGNORE_TLS_VALIDATION` | Disable TLS certificate validation when connecting to Keycloak. Do not use in production. |

### Example

```shell
./did-helper -didType=keycloak -keycloakHost=https://keycloak.example.com -server
```

Once running, the DID document for a realm `my-realm` would be available at:

```shell
# Encode the realm id in base64
REALM_B64=$(echo -n "my-realm" | base64)

# Request the DID document
curl http://localhost:8080/${REALM_B64}/did.json
```
