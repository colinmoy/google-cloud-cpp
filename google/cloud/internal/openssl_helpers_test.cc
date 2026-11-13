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
#include "google/cloud/testing_util/status_matchers.h"
#include <gmock/gmock.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace google {
namespace cloud {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace internal {
namespace {

using ::google::cloud::testing_util::StatusIs;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

struct OpenSslTestDeleter {
  void operator()(BIO* p) const { BIO_free(p); }
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
  void operator()(X509* p) const { X509_free(p); }
  void operator()(X509_CRL* p) const { X509_CRL_free(p); }
  void operator()(X509_STORE* p) const { X509_STORE_free(p); }
  void operator()(ASN1_TIME* p) const { ASN1_TIME_free(p); }
};

template <typename T>
using OpenSslPtr = std::unique_ptr<T, OpenSslTestDeleter>;

OpenSslPtr<EVP_PKEY> GenerateEcKey() {
  OpenSslPtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!ctx) return nullptr;
  if (EVP_PKEY_keygen_init(ctx.get()) != 1) return nullptr;
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) !=
      1) {
    return nullptr;
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) return nullptr;
  return OpenSslPtr<EVP_PKEY>(raw);
}

std::string BioToString(BIO* bio) {
  BUF_MEM* buf_mem = nullptr;
  BIO_get_mem_ptr(bio, &buf_mem);
  if (buf_mem == nullptr || buf_mem->data == nullptr) return {};
  return std::string(buf_mem->data, buf_mem->length);
}

OpenSslPtr<X509> GenerateSelfSignedCert(EVP_PKEY* key, std::string const& cn,
                                        long serial) {
  OpenSslPtr<X509> cert(X509_new());
  if (!cert) return nullptr;
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
  X509_set_pubkey(cert.get(), key);

  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<unsigned char const*>(cn.data()),
                             static_cast<int>(cn.size()), -1, 0);
  X509_set_issuer_name(cert.get(), name);

  if (X509_sign(cert.get(), key, EVP_sha256()) == 0) return nullptr;
  return cert;
}

std::string CertToPem(X509* cert) {
  OpenSslPtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) return {};
  return BioToString(bio.get());
}

std::string GenerateCrlPem(EVP_PKEY* key, X509* issuer_cert) {
  OpenSslPtr<X509_CRL> crl(X509_CRL_new());
  if (!crl) return {};
  X509_CRL_set_version(crl.get(), 1);
  X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer_cert));
  OpenSslPtr<ASN1_TIME> now(ASN1_TIME_new());
  X509_gmtime_adj(now.get(), 0);
  X509_CRL_set1_lastUpdate(crl.get(), now.get());
  if (X509_CRL_sign(crl.get(), key, EVP_sha256()) == 0) return {};

  OpenSslPtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_X509_CRL(bio.get(), crl.get()) != 1) return {};
  return BioToString(bio.get());
}

std::string KeyToPem(EVP_PKEY* key, bool encrypted) {
  OpenSslPtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio) return {};
  int const ok =
      encrypted ? PEM_write_bio_PKCS8PrivateKey(
                      bio.get(), key, EVP_aes_256_cbc(),
                      const_cast<char*>("secret"), 6, nullptr, nullptr)
                : PEM_write_bio_PKCS8PrivateKey(bio.get(), key, nullptr,
                                                nullptr, 0, nullptr, nullptr);
  if (ok != 1) return {};
  return BioToString(bio.get());
}

void PushDummySslError() {
  char const kNotAPem[] = "not a pem";
  OpenSslPtr<BIO> bio(BIO_new_mem_buf(kNotAPem, sizeof(kNotAPem) - 1));
  ASSERT_NE(bio, nullptr);
  OpenSslPtr<X509> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_EQ(cert, nullptr);
}

TEST(OpenSslHelpersTest, CaptureSslErrorsEmptyQueue) {
  ERR_clear_error();
  EXPECT_THAT(CaptureSslErrors(), IsEmpty());
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(OpenSslHelpersTest, CaptureSslErrorsDrainsMultipleErrors) {
  ERR_clear_error();
  PushDummySslError();
  PushDummySslError();
  ASSERT_NE(ERR_peek_error(), 0U);

  auto const msg = CaptureSslErrors();
  EXPECT_THAT(msg, Not(IsEmpty()));
  EXPECT_THAT(msg, HasSubstr(", "));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(OpenSslHelpersTest, AlwaysFailPasswordCallbackReturnsMinusOne) {
  auto* cb = AlwaysFailPasswordCallback();
  ASSERT_NE(cb, nullptr);
  char buf[16] = {};
  EXPECT_EQ(cb(buf, sizeof(buf), 0, nullptr), -1);
}

TEST(OpenSslHelpersTest, AddPemCertsToStoreRejectsNullStore) {
  auto const status = AddPemCertsToStore({}, nullptr);
  EXPECT_THAT(status, StatusIs(StatusCode::kInternal, HasSubstr("null")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(OpenSslHelpersTest, AddPemCertsToStoreRejectsZeroCerts) {
  OpenSslPtr<X509_STORE> store(X509_STORE_new());
  ASSERT_NE(store, nullptr);

  EXPECT_THAT(AddPemCertsToStore({}, store.get()),
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("No CA certificates found")));
  EXPECT_EQ(ERR_peek_error(), 0U);

  EXPECT_THAT(AddPemCertsToStore({""}, store.get()),
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("No CA certificates found")));
  EXPECT_EQ(ERR_peek_error(), 0U);

  EXPECT_THAT(AddPemCertsToStore({"not a pem certificate"}, store.get()),
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("No CA certificates found")));
  EXPECT_EQ(ERR_peek_error(), 0U);

  // A PEM private key without any certificates must also be rejected.
  auto key = GenerateEcKey();
  ASSERT_NE(key, nullptr);
  auto const key_pem = KeyToPem(key.get(), /*encrypted=*/false);
  ASSERT_THAT(key_pem, Not(IsEmpty()));
  EXPECT_THAT(AddPemCertsToStore({key_pem}, store.get()),
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("No CA certificates found")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(OpenSslHelpersTest, AddPemCertsToStoreRejectsMalformedPem) {
  OpenSslPtr<X509_STORE> store(X509_STORE_new());
  ASSERT_NE(store, nullptr);

  std::string_view constexpr kMalformedCert =
      "-----BEGIN CERTIFICATE-----\n"
      "!!!not-valid-base64!!!\n"
      "-----END CERTIFICATE-----\n";
  EXPECT_THAT(AddPemCertsToStore({kMalformedCert}, store.get()),
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("PEM_X509_INFO_read_bio failed")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(OpenSslHelpersTest,
     AddPemCertsToStoreRejectsEncryptedPemWithoutPrompting) {
  OpenSslPtr<X509_STORE> store(X509_STORE_new());
  ASSERT_NE(store, nullptr);

  auto key = GenerateEcKey();
  ASSERT_NE(key, nullptr);
  auto const encrypted_key_pem = KeyToPem(key.get(), /*encrypted=*/true);
  ASSERT_THAT(encrypted_key_pem, Not(IsEmpty()));

  // Must fail immediately (via AlwaysFailPasswordCallback) rather than
  // blocking on terminal input.
  auto const status = AddPemCertsToStore({encrypted_key_pem}, store.get());
  EXPECT_THAT(status, StatusIs(StatusCode::kInvalidArgument));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(OpenSslHelpersTest, AddPemCertsToStoreSuccessAndDuplicates) {
  auto key = GenerateEcKey();
  ASSERT_NE(key, nullptr);
  auto cert1 = GenerateSelfSignedCert(key.get(), "Test CA 1", 1);
  auto cert2 = GenerateSelfSignedCert(key.get(), "Test CA 2", 2);
  ASSERT_NE(cert1, nullptr);
  ASSERT_NE(cert2, nullptr);

  auto const pem1 = CertToPem(cert1.get());
  auto const pem2 = CertToPem(cert2.get());
  auto const crl_pem = GenerateCrlPem(key.get(), cert1.get());
  ASSERT_THAT(pem1, Not(IsEmpty()));
  ASSERT_THAT(pem2, Not(IsEmpty()));
  ASSERT_THAT(crl_pem, Not(IsEmpty()));

  OpenSslPtr<X509_STORE> store(X509_STORE_new());
  ASSERT_NE(store, nullptr);

  // Add multiple certs + CRL in a single call.
  ASSERT_STATUS_OK(AddPemCertsToStore({pem1, pem2 + crl_pem}, store.get()));
  EXPECT_EQ(ERR_peek_error(), 0U);

  // Re-adding duplicate certs and CRLs should succeed cleanly without leaving
  // X509_R_CERT_ALREADY_IN_HASH_TABLE on the error queue.
  ASSERT_STATUS_OK(AddPemCertsToStore({pem1, crl_pem}, store.get()));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

}  // namespace
}  // namespace internal
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace cloud
}  // namespace google
#endif  // _WIN32
