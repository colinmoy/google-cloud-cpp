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
#include "google/cloud/internal/parse_service_account_p12_file.h"
#include "google/cloud/internal/filesystem.h"
#include "google/cloud/internal/random.h"
#include "google/cloud/internal/sign_using_sha256.h"
#include "google/cloud/testing_util/status_matchers.h"
#include <gmock/gmock.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <cstdio>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace google {
namespace cloud {
namespace oauth2_internal {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace {

using ::google::cloud::testing_util::StatusIs;
using ::testing::AnyOf;
using ::testing::HasSubstr;
using ::testing::StartsWith;

struct OpenSslTestDeleter {
  void operator()(BIO* p) const { BIO_free(p); }
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
  void operator()(PKCS12* p) const { PKCS12_free(p); }
  void operator()(X509* p) const { X509_free(p); }
};

template <typename T>
using OpenSslPtr = std::unique_ptr<T, OpenSslTestDeleter>;

class ScopedTempFile {
 public:
  explicit ScopedTempFile(std::string path) : path_(std::move(path)) {}
  ~ScopedTempFile() { std::remove(path_.c_str()); }

  ScopedTempFile(ScopedTempFile const&) = delete;
  ScopedTempFile& operator=(ScopedTempFile const&) = delete;

  std::string const& path() const { return path_; }

 private:
  std::string path_;
};

std::string MakeTempP12Path() {
  static auto generator =
      google::cloud::internal::DefaultPRNG(std::random_device{}());
  return google::cloud::internal::PathAppend(
      ::testing::TempDir(),
      google::cloud::internal::Sample(generator, 16,
                                      "abcdefghijklmnopqrstuvwxyz0123456789") +
          ".p12");
}

OpenSslPtr<EVP_PKEY> GenerateRsaKey() {
  OpenSslPtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx) return nullptr;
  if (EVP_PKEY_keygen_init(ctx.get()) != 1) return nullptr;
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) != 1) return nullptr;
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) return nullptr;
  return OpenSslPtr<EVP_PKEY>(raw);
}

OpenSslPtr<X509> GenerateSelfSignedCert(
    EVP_PKEY* key,
    std::vector<std::pair<std::string, std::string>> const& rdns) {
  OpenSslPtr<X509> cert(X509_new());
  if (!cert) return nullptr;
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
  X509_set_pubkey(cert.get(), key);

  X509_NAME* name = X509_get_subject_name(cert.get());
  for (auto const& kv : rdns) {
    if (X509_NAME_add_entry_by_txt(
            name, kv.first.c_str(), MBSTRING_UTF8,
            reinterpret_cast<unsigned char const*>(kv.second.data()),
            static_cast<int>(kv.second.size()), -1, 0) != 1) {
      return nullptr;
    }
  }
  X509_set_issuer_name(cert.get(), name);

  if (X509_sign(cert.get(), key, EVP_sha256()) == 0) return nullptr;
  return cert;
}

bool WriteP12File(std::string const& path, char const* password, EVP_PKEY* key,
                  X509* cert) {
  OpenSslPtr<PKCS12> p12(
      PKCS12_create(password, nullptr, key, cert, nullptr, 0, 0, 0, 0, 0));
  if (!p12) return false;
  OpenSslPtr<BIO> bio(BIO_new_file(path.c_str(), "wb"));
  if (!bio) return false;
  return i2d_PKCS12_bio(bio.get(), p12.get()) == 1;
}

TEST(ParseServiceAccountP12FileTest, ValidNumericCommonName) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert =
      GenerateSelfSignedCert(key.get(), {{"CN", "104849618361176160538"}});
  ASSERT_NE(cert, nullptr);

  ScopedTempFile file(MakeTempP12Path());
  ASSERT_TRUE(WriteP12File(file.path(), "notasecret", key.get(), cert.get()));

  auto const info = ParseServiceAccountP12File(file.path());
  ASSERT_STATUS_OK(info);
  EXPECT_EQ(info->client_email, "104849618361176160538");
  EXPECT_EQ(info->private_key_id, P12PrivateKeyIdMarker());
  EXPECT_THAT(info->private_key, StartsWith("-----BEGIN PRIVATE KEY-----"));
  EXPECT_EQ(ERR_peek_error(), 0U);

  auto const sig =
      google::cloud::internal::SignUsingSha256("hello", info->private_key);
  ASSERT_STATUS_OK(sig);
}

TEST(ParseServiceAccountP12FileTest, ValidCommonNameWithAdditionalRdns) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert = GenerateSelfSignedCert(
      key.get(), {{"O", "Example Corp"}, {"CN", "9876543210"}, {"C", "US"}});
  ASSERT_NE(cert, nullptr);

  ScopedTempFile file(MakeTempP12Path());
  ASSERT_TRUE(WriteP12File(file.path(), "notasecret", key.get(), cert.get()));

  auto const info = ParseServiceAccountP12File(file.path());
  ASSERT_STATUS_OK(info);
  EXPECT_EQ(info->client_email, "9876543210");
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(ParseServiceAccountP12FileTest, MissingCommonName) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert = GenerateSelfSignedCert(key.get(), {{"O", "Example Corp"}});
  ASSERT_NE(cert, nullptr);

  ScopedTempFile file(MakeTempP12Path());
  ASSERT_TRUE(WriteP12File(file.path(), "notasecret", key.get(), cert.get()));

  auto const info = ParseServiceAccountP12File(file.path());
  EXPECT_THAT(info, StatusIs(StatusCode::kInvalidArgument,
                             HasSubstr("service account id missing or not "
                                       "formatted correctly")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(ParseServiceAccountP12FileTest, MultipleCommonNamesRejected) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert =
      GenerateSelfSignedCert(key.get(), {{"CN", "12345"}, {"CN", "67890"}});
  ASSERT_NE(cert, nullptr);

  ScopedTempFile file(MakeTempP12Path());
  ASSERT_TRUE(WriteP12File(file.path(), "notasecret", key.get(), cert.get()));

  auto const info = ParseServiceAccountP12File(file.path());
  EXPECT_THAT(info, StatusIs(StatusCode::kInvalidArgument,
                             HasSubstr("service account id missing or not "
                                       "formatted correctly")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(ParseServiceAccountP12FileTest, NonNumericCommonNameRejected) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert = GenerateSelfSignedCert(key.get(), {{"CN", "not-numeric"}});
  ASSERT_NE(cert, nullptr);

  ScopedTempFile file(MakeTempP12Path());
  ASSERT_TRUE(WriteP12File(file.path(), "notasecret", key.get(), cert.get()));

  auto const info = ParseServiceAccountP12File(file.path());
  EXPECT_THAT(info, StatusIs(StatusCode::kInvalidArgument,
                             HasSubstr("service account id missing or not "
                                       "formatted correctly")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(ParseServiceAccountP12FileTest, WrongPasswordDrainsErrorQueue) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert = GenerateSelfSignedCert(key.get(), {{"CN", "12345"}});
  ASSERT_NE(cert, nullptr);

  ScopedTempFile file(MakeTempP12Path());
  ASSERT_TRUE(
      WriteP12File(file.path(), "wrongpassword", key.get(), cert.get()));

  auto const info = ParseServiceAccountP12File(file.path());
  EXPECT_THAT(info, StatusIs(StatusCode::kInvalidArgument,
                             HasSubstr("Cannot parse PKCS#12 file")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(ParseServiceAccountP12FileTest, MissingPrivateKeyOrCert) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto cert = GenerateSelfSignedCert(key.get(), {{"CN", "12345"}});
  ASSERT_NE(cert, nullptr);

  {
    ScopedTempFile file(MakeTempP12Path());
    ASSERT_TRUE(WriteP12File(file.path(), "notasecret", nullptr, cert.get()));
    auto const info = ParseServiceAccountP12File(file.path());
    EXPECT_THAT(info, StatusIs(StatusCode::kInvalidArgument,
                               HasSubstr("No private key found")));
    EXPECT_EQ(ERR_peek_error(), 0U);
  }

  {
    ScopedTempFile file(MakeTempP12Path());
    ASSERT_TRUE(WriteP12File(file.path(), "notasecret", key.get(), nullptr));
    auto const info = ParseServiceAccountP12File(file.path());
    EXPECT_THAT(info, StatusIs(StatusCode::kInvalidArgument,
                               HasSubstr("No certificate found")));
    EXPECT_EQ(ERR_peek_error(), 0U);
  }
}

TEST(ParseServiceAccountP12FileTest, NonExistentAndCorruptFile) {
  auto const missing = ParseServiceAccountP12File(MakeTempP12Path());
  EXPECT_THAT(missing, StatusIs(StatusCode::kInvalidArgument,
                                HasSubstr("Cannot open PKCS#12 file")));
  EXPECT_EQ(ERR_peek_error(), 0U);

  ScopedTempFile corrupt(MakeTempP12Path());
  {
    std::ofstream os(corrupt.path(), std::ios::binary);
    os << "definitely-not-a-pkcs12-file";
  }
  auto const bad = ParseServiceAccountP12File(corrupt.path());
  EXPECT_THAT(bad, StatusIs(StatusCode::kInvalidArgument,
                            AnyOf(HasSubstr("Cannot read PKCS#12 file"),
                                  HasSubstr("Cannot parse PKCS#12 file"))));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

}  // namespace
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace oauth2_internal
}  // namespace cloud
}  // namespace google
#endif  // _WIN32
