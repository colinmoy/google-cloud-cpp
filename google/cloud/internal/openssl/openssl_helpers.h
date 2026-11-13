// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_OPENSSL_OPENSSL_HELPERS_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_OPENSSL_OPENSSL_HELPERS_H

#ifndef _WIN32
#include "google/cloud/status.h"
#include "google/cloud/version.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>
#include <vector>

namespace google {
namespace cloud {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace internal {

/**
 * Drains the thread-local OpenSSL/BoringSSL error queue and formats all
 * queued errors into a single comma-separated string.
 */
std::string CaptureSslErrors();

/**
 * Returns a `pem_password_cb` that always fails immediately instead of
 * prompting on the terminal when OpenSSL encounters an encrypted PEM object.
 */
pem_password_cb* AlwaysFailPasswordCallback();

/**
 * Parses PEM-encoded CA certificates (and optional CRLs) from `ca_certs` and
 * adds them to `cert_store`.
 *
 * Returns an error if any OpenSSL call fails (other than duplicate certificate
 * or CRL entries already present in `cert_store`) or if zero certificates were
 * found across `ca_certs`.
 */
Status AddPemCertsToStore(std::vector<std::string_view> const& ca_certs,
                          X509_STORE* cert_store);

}  // namespace internal
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace cloud
}  // namespace google
#endif  // _WIN32

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_OPENSSL_OPENSSL_HELPERS_H
