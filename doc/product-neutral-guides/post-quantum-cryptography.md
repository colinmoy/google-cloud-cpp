# Google Cloud Platform C++ Client Libraries: Post-Quantum Cryptography (PQC)

The Google Cloud C++ Client Libraries support Post-Quantum Cryptography (PQC)
for TLS 1.3 connections to protect network traffic against "harvest now, decrypt
later" attacks.

By default, both gRPC and REST transports negotiate the hybrid post-quantum key
exchange mechanism **`X25519MLKEM768`** (combining classical `X25519` ECDH with
NIST-standardized `ML-KEM-768`) whenever supported by the underlying TLS and
cryptographic libraries.

## 1. Default Behavior by Transport

No code changes are required to use PQC when building with supported dependency
versions:

| Transport | Default Behavior                                         | Minimum Dependency Requirements                        |
| --------- | -------------------------------------------------------- | ------------------------------------------------------ |
| **gRPC**  | Enabled automatically by gRPC and its TLS stack.         | gRPC built with BoringSSL or OpenSSL >= 3.5.0          |
| **REST**  | Enabled automatically by BoringSSL and OpenSSL >= 3.5.0. | `libcurl >= 7.73.0` with BoringSSL or OpenSSL >= 3.5.0 |

### REST Transport Details

By default, the REST client uses the underlying TLS library's default key
exchange group preference (OpenSSL >= 3.5.0 and recent BoringSSL versions
already prioritize `X25519MLKEM768` by default). For BoringSSL builds that
support `X25519MLKEM768`, the client sets `CURLOPT_SSL_EC_CURVES` to
`X25519MLKEM768:X25519:P-256:P-384` so `X25519MLKEM768` is offered even on older
BoringSSL releases that did not yet enable it by default.

## 2. Disabling Post-Quantum Cryptography

In certain network environments, legacy firewalls, proxies, or middleboxes may
drop or time out TLS handshakes containing larger hybrid post-quantum
`ClientHello` key shares. If you encounter TLS handshake failures, you can opt
out of PQC.

### Disabling PQC with REST

Set the `GOOGLE_CLOUD_CPP_DISABLE_PQC` environment variable to any value before
starting your application:

```
export GOOGLE_CLOUD_CPP_DISABLE_PQC="true"
./my_application
```

When `GOOGLE_CLOUD_CPP_DISABLE_PQC` is set, the REST client configures
`CURLOPT_SSL_EC_CURVES` to classical curves only (`X25519:P-256:P-384`),
disabling post-quantum key exchange groups (requires `libcurl >= 7.73.0` with a
supported TLS backend such as OpenSSL or BoringSSL).

### Disabling PQC with gRPC

The `GOOGLE_CLOUD_CPP_DISABLE_PQC` environment variable only applies to REST
clients. Neither `google-cloud-cpp` nor upstream C++ gRPC provides an
environment variable to disable `X25519MLKEM768` on default credentials.

To restrict a gRPC client to classical TLS key exchange groups, configure custom
TLS channel credentials using `grpc::experimental::TlsChannelCredentialsOptions`
and pass them via `google::cloud::GrpcCredentialOption`:

```cpp
#include "google/cloud/common_options.h"
#include "google/cloud/grpc_options.h"
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_credentials_options.h>

google::cloud::Options ConfigureClassicalTlsForGrpc(
    std::shared_ptr<grpc::CallCredentials> call_credentials) {
  grpc::experimental::TlsChannelCredentialsOptions tls_options;
  tls_options.set_key_exchange_groups({
      GRPC_TLS_KEY_EXCHANGE_GROUP_X25519,
      GRPC_TLS_KEY_EXCHANGE_GROUP_SECP256R1,
  });

  auto channel_credentials = grpc::CompositeChannelCredentials(
      grpc::experimental::TlsCredentials(tls_options),
      std::move(call_credentials));

  return google::cloud::Options{}
      .set<google::cloud::GrpcCredentialOption>(std::move(channel_credentials));
}
```
