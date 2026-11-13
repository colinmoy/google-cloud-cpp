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

#include "google/cloud/internal/ssl_ec_curves.h"
#include "google/cloud/internal/getenv.h"
#include "google/cloud/internal/make_status.h"
#include "absl/strings/match.h"
#include <curl/curl.h>
#ifdef GOOGLE_CLOUD_CPP_HAVE_OPENSSL
#include <openssl/ssl.h>
#endif
#include <string_view>

namespace google {
namespace cloud {
namespace rest_internal {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace {

// libcurl encodes version Ma.Mi.Pa as (Ma << 16) | (Mi << 8) | Pa.
// CURLOPT_SSL_EC_CURVES was introduced in libcurl version 7.73.0.
constexpr unsigned int kMinimumLibcurlVersionForEcCurves =
    (7U << 16) | (73U << 8) | 0U;

// Classical-only TLS key exchange groups used when PQC is explicitly disabled
// via `GOOGLE_CLOUD_CPP_DISABLE_PQC`.
std::string_view constexpr kClassicalEcCurves = "X25519:P-256:P-384";

// Explicit PQC-preferred TLS key exchange groups for BoringSSL builds whose
// default group list does not yet include X25519MLKEM768.
std::string_view constexpr kBoringSslPqcEcCurves =
    "X25519MLKEM768:X25519:P-256:P-384";

// `curl_version_info()` is not thread-safe as libcurl constructs version
// string details in internal static buffers without locks. Using a block-scope
// static ensures thread-safe initialization exactly once via C++11 magic
// statics, preventing data races when multiple threads create REST clients.
bool SupportsSslEcCurves() {
  static bool const kSupports = [] {
    auto* vinfo = curl_version_info(CURLVERSION_NOW);
    if (vinfo == nullptr ||
        vinfo->version_num < kMinimumLibcurlVersionForEcCurves ||
        vinfo->ssl_version == nullptr) {
      return false;
    }
    // libcurl only implements CURLOPT_SSL_EC_CURVES for OpenSSL-compatible
    // backends and wolfSSL. Setting it on other backends (e.g., Schannel or
    // SecureTransport) fails with CURLE_NOT_BUILT_IN.
    std::string_view const ssl_version(vinfo->ssl_version);
    return absl::StartsWith(ssl_version, "OpenSSL") ||
           absl::StartsWith(ssl_version, "BoringSSL") ||
           absl::StartsWith(ssl_version, "LibreSSL") ||
           absl::StartsWith(ssl_version, "AWS-LC") ||
           absl::StartsWith(ssl_version, "quictls") ||
           absl::StartsWith(ssl_version, "wolfSSL");
  }();
  return kSupports;
}

bool NeedsExplicitBoringSslPqc() {
#if defined(GOOGLE_CLOUD_CPP_HAVE_OPENSSL) && defined(OPENSSL_IS_BORINGSSL) && \
    defined(SSL_GROUP_X25519_MLKEM768)
  return true;
#else
  return false;
#endif
}

}  // namespace

StatusOr<std::string> ResolvePqcEcCurves(bool disable_pqc,
                                         bool supports_ssl_ec_curves,
                                         bool enable_pqc_explicitly) {
  if (disable_pqc) {
    if (!supports_ssl_ec_curves) {
      return internal::UnavailableError(
          "Cannot disable PQC: CURLOPT_SSL_EC_CURVES requires libcurl 7.73.0 "
          "or later with a supported TLS backend.",
          GCP_ERROR_INFO());
    }
    return std::string(kClassicalEcCurves);
  }
  if (enable_pqc_explicitly) {
    if (!supports_ssl_ec_curves) {
      return internal::UnavailableError(
          "CURLOPT_SSL_EC_CURVES requires libcurl 7.73.0 or later with a "
          "supported TLS backend.",
          GCP_ERROR_INFO());
    }
    return std::string(kBoringSslPqcEcCurves);
  }
  // Leave the underlying TLS library's default group list untouched. Modern
  // OpenSSL (>= 3.5) and BoringSSL already prioritize X25519MLKEM768 by
  // default; older OpenSSL and non-OpenSSL backends use their own defaults.
  return std::string{};
}

StatusOr<std::string> GetPqcEcCurves() {
  return ResolvePqcEcCurves(
      internal::GetEnv("GOOGLE_CLOUD_CPP_DISABLE_PQC").has_value(),
      SupportsSslEcCurves(), NeedsExplicitBoringSslPqc());
}

GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace rest_internal
}  // namespace cloud
}  // namespace google
