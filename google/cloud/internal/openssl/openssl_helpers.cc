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

#ifndef _WIN32
#include "google/cloud/internal/openssl/openssl_helpers.h"
#include "google/cloud/internal/make_status.h"
#include "absl/strings/str_cat.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <array>
#include <cstddef>
#include <limits>
#include <memory>

namespace google {
namespace cloud {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace internal {

namespace {

extern "C" {
static int
AlwaysFailPasswordCallbackImpl(  // NOLINT(misc-use-anonymous-namespace)
    char*, int, int, void*) {
  return -1;
}
}  // extern "C"

struct BioDeleter {
  void operator()(BIO* b) const { BIO_free(b); }
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;

struct X509InfoStackDeleter {
  void operator()(STACK_OF(X509_INFO) * i) const {
    sk_X509_INFO_pop_free(i, X509_INFO_free);
  }
};

using X509InfoStackPtr =
    std::unique_ptr<STACK_OF(X509_INFO), X509InfoStackDeleter>;

bool IsAlreadyInHashTableError() {
  auto const err = ERR_peek_last_error();
  return ERR_GET_LIB(err) == ERR_LIB_X509 &&
         ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE;
}

}  // namespace

std::string CaptureSslErrors() {
  std::string msg;
  char const* sep = "";
  while (auto code = ERR_get_error()) {
    // OpenSSL guarantees that 256 bytes is enough:
    //   https://www.openssl.org/docs/man1.1.1/man3/ERR_error_string_n.html
    //   https://www.openssl.org/docs/man1.0.2/man3/ERR_error_string_n.html
    // we could not find a macro or constant to replace the 256 literal.
    auto constexpr kMaxOpenSslErrorLength = 256;
    std::array<char, kMaxOpenSslErrorLength> buf{};
    ERR_error_string_n(code, buf.data(), buf.size());
    msg += sep;
    msg += buf.data();
    sep = ", ";
  }
  return msg;
}

pem_password_cb* AlwaysFailPasswordCallback() {
  return &AlwaysFailPasswordCallbackImpl;
}

Status AddPemCertsToStore(std::vector<std::string_view> const& ca_certs,
                          X509_STORE* cert_store) {
  ERR_clear_error();
  if (!cert_store) {
    return InternalError("X509_STORE is null", GCP_ERROR_INFO());
  }

  auto constexpr kOpenSslSuccess = 1;
  std::size_t certs_added = 0;

  for (auto const& cert : ca_certs) {
    if (cert.empty()) continue;
    if (cert.size() >
        static_cast<std::size_t>(std::numeric_limits<int>::max())) {
      return InvalidArgumentError("CA certificate PEM data is too large",
                                  GCP_ERROR_INFO());
    }
    BioPtr buf{BIO_new_mem_buf(cert.data(), static_cast<int>(cert.size()))};
    if (!buf) {
      return InternalError(
          absl::StrCat("BIO_new_mem_buf returned NULL: ", CaptureSslErrors()),
          GCP_ERROR_INFO());
    }
    X509InfoStackPtr info{PEM_X509_INFO_read_bio(
        buf.get(), nullptr, AlwaysFailPasswordCallback(), nullptr)};
    if (!info) {
      return InvalidArgumentError(
          absl::StrCat("PEM_X509_INFO_read_bio failed: ", CaptureSslErrors()),
          GCP_ERROR_INFO());
    }
    // PEM_X509_INFO_read_bio clears PEM_R_NO_START_LINE on EOF, but clear the
    // error queue here to avoid leaking any leftover state.
    ERR_clear_error();

    for (decltype(sk_X509_INFO_num(info.get())) i = 0;
         i < sk_X509_INFO_num(info.get()); ++i) {
      X509_INFO* value = sk_X509_INFO_value(info.get(), i);
      if (value == nullptr) continue;
      if (value->x509 != nullptr) {
        ERR_clear_error();
        if (X509_STORE_add_cert(cert_store, value->x509) != kOpenSslSuccess) {
          if (IsAlreadyInHashTableError()) {
            ERR_clear_error();
          } else {
            return InternalError(absl::StrCat("X509_STORE_add_cert failed: ",
                                              CaptureSslErrors()),
                                 GCP_ERROR_INFO());
          }
        }
        ++certs_added;
      }
      if (value->crl != nullptr) {
        ERR_clear_error();
        if (X509_STORE_add_crl(cert_store, value->crl) != kOpenSslSuccess) {
          if (IsAlreadyInHashTableError()) {
            ERR_clear_error();
          } else {
            return InternalError(
                absl::StrCat("X509_STORE_add_crl failed: ", CaptureSslErrors()),
                GCP_ERROR_INFO());
          }
        }
      }
    }
  }

  if (certs_added == 0) {
    return InvalidArgumentError(
        "No CA certificates found in the provided PEM data", GCP_ERROR_INFO());
  }

  return {};
}

}  // namespace internal
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace cloud
}  // namespace google
#endif  // _WIN32
