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
#include "google/cloud/internal/sign_using_sha256.h"
#include "google/cloud/testing_util/status_matchers.h"
#include <gmock/gmock.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <memory>
#include <string>

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
  void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};

template <typename T>
using OpenSslPtr = std::unique_ptr<T, OpenSslTestDeleter>;

OpenSslPtr<EVP_PKEY> GenerateRsaKey() {
  OpenSslPtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx) return nullptr;
  if (EVP_PKEY_keygen_init(ctx.get()) != 1) return nullptr;
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) != 1) return nullptr;
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) return nullptr;
  return OpenSslPtr<EVP_PKEY>(raw);
}

OpenSslPtr<EVP_PKEY> GenerateEcP256Key() {
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

std::string ExportPrivateKeyPem(EVP_PKEY* key, bool encrypted) {
  OpenSslPtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio) return {};
  int const ok =
      encrypted ? PEM_write_bio_PKCS8PrivateKey(
                      bio.get(), key, EVP_aes_256_cbc(),
                      const_cast<char*>("secret"), 6, nullptr, nullptr)
                : PEM_write_bio_PKCS8PrivateKey(bio.get(), key, nullptr,
                                                nullptr, 0, nullptr, nullptr);
  if (ok != 1) return {};
  BUF_MEM* buf_mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &buf_mem);
  if (buf_mem == nullptr || buf_mem->data == nullptr) return {};
  return std::string(buf_mem->data, buf_mem->length);
}

bool VerifyDerSignature(EVP_PKEY* key, std::string const& message,
                        std::vector<std::uint8_t> const& sig) {
  OpenSslPtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
  if (!ctx) return false;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) !=
      1) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) != 1) {
    return false;
  }
  return EVP_DigestVerifyFinal(ctx.get(), sig.data(), sig.size()) == 1;
}

TEST(SignUsingSha256Test, RsaDerSuccess) {
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto const pem = ExportPrivateKeyPem(key.get(), /*encrypted=*/false);
  ASSERT_THAT(pem, Not(IsEmpty()));

  std::string const message = "test-payload-rsa";
  auto const sig = SignUsingSha256(message, pem, SignatureFormat::kDER);
  ASSERT_STATUS_OK(sig);
  EXPECT_TRUE(VerifyDerSignature(key.get(), message, *sig));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(SignUsingSha256Test, EcdsaDerAndRawSuccess) {
  auto key = GenerateEcP256Key();
  ASSERT_NE(key, nullptr);
  auto const pem = ExportPrivateKeyPem(key.get(), /*encrypted=*/false);
  ASSERT_THAT(pem, Not(IsEmpty()));

  std::string const message = "test-payload-ecdsa";
  auto const der_sig = SignUsingSha256(message, pem, SignatureFormat::kDER);
  ASSERT_STATUS_OK(der_sig);
  EXPECT_TRUE(VerifyDerSignature(key.get(), message, *der_sig));
  EXPECT_EQ(ERR_peek_error(), 0U);

  auto const raw_sig = SignUsingSha256(message, pem, SignatureFormat::kRaw);
  ASSERT_STATUS_OK(raw_sig);
  EXPECT_EQ(raw_sig->size(), 64U);
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(SignUsingSha256Test, DerToRawFailureDrainsErrorQueue) {
  // Signing with an RSA key produces a PKCS#1 signature (not an ASN.1
  // ECDSA_SIG), so requesting kRaw exercises the DERToRawSignature error path.
  auto key = GenerateRsaKey();
  ASSERT_NE(key, nullptr);
  auto const pem = ExportPrivateKeyPem(key.get(), /*encrypted=*/false);
  ASSERT_THAT(pem, Not(IsEmpty()));

  auto const sig = SignUsingSha256("payload", pem, SignatureFormat::kRaw);
  EXPECT_THAT(sig, StatusIs(StatusCode::kInvalidArgument,
                            HasSubstr("Error parsing DER signature:")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(SignUsingSha256Test, EncryptedPemFailsImmediatelyWithoutPrompting) {
  auto key = GenerateEcP256Key();
  ASSERT_NE(key, nullptr);
  auto const encrypted_pem = ExportPrivateKeyPem(key.get(), /*encrypted=*/true);
  ASSERT_THAT(encrypted_pem, HasSubstr("ENCRYPTED PRIVATE KEY"));

  auto const sig =
      SignUsingSha256("payload", encrypted_pem, SignatureFormat::kDER);
  EXPECT_THAT(sig, StatusIs(StatusCode::kInvalidArgument,
                            HasSubstr("could not parse PEM")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

TEST(SignUsingSha256Test, InvalidPemDrainsErrorQueue) {
  auto const sig = SignUsingSha256("payload", "not-a-valid-pem");
  EXPECT_THAT(sig, StatusIs(StatusCode::kInvalidArgument,
                            HasSubstr("could not parse PEM")));
  EXPECT_EQ(ERR_peek_error(), 0U);
}

}  // namespace
}  // namespace internal
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace cloud
}  // namespace google
#endif  // _WIN32
