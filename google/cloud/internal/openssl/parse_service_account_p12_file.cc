// Copyright 2024 Google LLC
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

#ifndef _WIN32
#include "google/cloud/internal/parse_service_account_p12_file.h"
#include "google/cloud/internal/make_status.h"
#include "google/cloud/internal/openssl/openssl_helpers.h"
#include "absl/strings/str_cat.h"
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace google {
namespace cloud {
namespace oauth2_internal {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN

namespace {

struct OpenSslFreeDeleter {
  void operator()(unsigned char* ptr) const { OPENSSL_free(ptr); }
};

std::optional<std::string> ExtractCommonName(X509_NAME* name) {
  if (name == nullptr) return std::nullopt;
  int const index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (index < 0) return std::nullopt;
  // Reject certificates with multiple Common Name (CN) entries.
  if (X509_NAME_get_index_by_NID(name, NID_commonName, index) >= 0) {
    return std::nullopt;
  }
  X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
  if (entry == nullptr) return std::nullopt;
  ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
  if (data == nullptr) return std::nullopt;
  unsigned char* utf8_raw = nullptr;
  int const len = ASN1_STRING_to_UTF8(&utf8_raw, data);
  if (len < 0 || utf8_raw == nullptr) {
    ERR_clear_error();
    return std::nullopt;
  }
  std::unique_ptr<unsigned char, OpenSslFreeDeleter> utf8(utf8_raw);
  return std::string(reinterpret_cast<char const*>(utf8.get()),
                     static_cast<std::size_t>(len));
}

}  // namespace

StatusOr<ServiceAccountCredentialsInfo> ParseServiceAccountP12File(
    std::string const& source) {
  OpenSSL_add_all_algorithms();
  ERR_clear_error();

  std::unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_file(source.c_str(), "rb"), &BIO_free);
  if (!bio) {
    return internal::InvalidArgumentError(
        absl::StrCat("Cannot open PKCS#12 file (", source,
                     "): ", internal::CaptureSslErrors()),
        GCP_ERROR_INFO());
  }

  std::unique_ptr<PKCS12, decltype(&PKCS12_free)> p12(
      d2i_PKCS12_bio(bio.get(), nullptr), &PKCS12_free);
  if (!p12) {
    return internal::InvalidArgumentError(
        absl::StrCat("Cannot read PKCS#12 file (", source,
                     "): ", internal::CaptureSslErrors()),
        GCP_ERROR_INFO());
  }

  EVP_PKEY* pkey_raw = nullptr;
  X509* cert_raw = nullptr;
  if (PKCS12_parse(p12.get(), "notasecret", &pkey_raw, &cert_raw, nullptr) !=
      1) {
    return internal::InvalidArgumentError(
        absl::StrCat("Cannot parse PKCS#12 file (", source,
                     "): ", internal::CaptureSslErrors()),
        GCP_ERROR_INFO());
  }

  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(pkey_raw,
                                                           &EVP_PKEY_free);
  std::unique_ptr<X509, decltype(&X509_free)> cert(cert_raw, &X509_free);

  if (pkey_raw == nullptr) {
    return internal::InvalidArgumentError(
        absl::StrCat("No private key found in PKCS#12 file (", source, ")"),
        GCP_ERROR_INFO());
  }
  if (cert_raw == nullptr) {
    return internal::InvalidArgumentError(
        absl::StrCat("No certificate found in PKCS#12 file (", source, ")"),
        GCP_ERROR_INFO());
  }

  // This is automatically deleted by `cert`.
  X509_NAME* name = X509_get_subject_name(cert.get());
  auto service_account_id = ExtractCommonName(name);
  if (!service_account_id || service_account_id->empty() ||
      service_account_id->find_first_not_of("0123456789") !=
          std::string::npos) {
    return internal::InvalidArgumentError(
        absl::StrCat("Invalid PKCS#12 file (", source,
                     "): service account id missing or not formatted "
                     "correctly"),
        GCP_ERROR_INFO());
  }

  std::unique_ptr<BIO, decltype(&BIO_free)> mem_io(BIO_new(BIO_s_mem()),
                                                   &BIO_free);
  if (!mem_io) {
    return internal::UnknownError(
        absl::StrCat("Cannot allocate BIO for PKCS#12 file (", source,
                     "): ", internal::CaptureSslErrors()),
        GCP_ERROR_INFO());
  }

  if (PEM_write_bio_PKCS8PrivateKey(mem_io.get(), pkey.get(), nullptr, nullptr,
                                    0, nullptr, nullptr) != 1) {
    return internal::UnknownError(
        absl::StrCat("Cannot print private key in PKCS#12 file (", source,
                     "): ", internal::CaptureSslErrors()),
        GCP_ERROR_INFO());
  }

  // This buffer belongs to the BIO chain and is freed upon its destruction.
  BUF_MEM* buf_mem = nullptr;
  BIO_get_mem_ptr(mem_io.get(), &buf_mem);
  if (buf_mem == nullptr || buf_mem->data == nullptr) {
    return internal::UnknownError(
        absl::StrCat("Cannot read private key buffer from PKCS#12 file (",
                     source, "): ", internal::CaptureSslErrors()),
        GCP_ERROR_INFO());
  }

  std::string private_key(buf_mem->data, buf_mem->length);

  return ServiceAccountCredentialsInfo{*std::move(service_account_id),
                                       P12PrivateKeyIdMarker(),
                                       std::move(private_key),
                                       GoogleOAuthRefreshEndpoint(),
                                       /*scopes=*/{},
                                       /*subject=*/{},
                                       /*enable_self_signed_jwt=*/false,
                                       /*universe_domain=*/std::nullopt,
                                       /*project_id=*/std::nullopt};
}

GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace oauth2_internal
}  // namespace cloud
}  // namespace google
#endif
