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
#include "google/cloud/testing_util/scoped_environment.h"
#include "google/cloud/testing_util/status_matchers.h"
#include <gmock/gmock.h>
#include <optional>

namespace google {
namespace cloud {
namespace rest_internal {
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_BEGIN
namespace {

using ::google::cloud::testing_util::IsOkAndHolds;
using ::google::cloud::testing_util::ScopedEnvironment;
using ::google::cloud::testing_util::StatusIs;
using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

TEST(SslEcCurvesTest, DefaultLeavesTlsLibraryDefaultsUntouched) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/false,
                                   /*supports_ssl_ec_curves=*/true,
                                   /*enable_pqc_explicitly=*/false);
  EXPECT_THAT(actual, IsOkAndHolds(IsEmpty()));
}

TEST(SslEcCurvesTest, DefaultWithoutCurlSupportLeavesDefaultsUntouched) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/false,
                                   /*supports_ssl_ec_curves=*/false,
                                   /*enable_pqc_explicitly=*/false);
  EXPECT_THAT(actual, IsOkAndHolds(IsEmpty()));
}

TEST(SslEcCurvesTest, ExplicitPqcPreferredGroupOrder) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/false,
                                   /*supports_ssl_ec_curves=*/true,
                                   /*enable_pqc_explicitly=*/true);
  EXPECT_THAT(actual, IsOkAndHolds("X25519MLKEM768:X25519:P-256:P-384"));
}

TEST(SslEcCurvesTest, ExplicitPqcUnsupportedLibcurl) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/false,
                                   /*supports_ssl_ec_curves=*/false,
                                   /*enable_pqc_explicitly=*/true);
  EXPECT_THAT(actual, StatusIs(StatusCode::kUnavailable,
                               HasSubstr("libcurl 7.73.0 or later")));
}

TEST(SslEcCurvesTest, DisablePqcReturnsClassicalCurvesOnly) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/true,
                                   /*supports_ssl_ec_curves=*/true,
                                   /*enable_pqc_explicitly=*/false);
  EXPECT_THAT(actual, IsOkAndHolds("X25519:P-256:P-384"));
}

TEST(SslEcCurvesTest, DisablePqcOverridesExplicitPqc) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/true,
                                   /*supports_ssl_ec_curves=*/true,
                                   /*enable_pqc_explicitly=*/true);
  EXPECT_THAT(actual, IsOkAndHolds("X25519:P-256:P-384"));
}

TEST(SslEcCurvesTest, DisablePqcUnsupportedLibcurl) {
  auto actual = ResolvePqcEcCurves(/*disable_pqc=*/true,
                                   /*supports_ssl_ec_curves=*/false,
                                   /*enable_pqc_explicitly=*/false);
  EXPECT_THAT(actual, StatusIs(StatusCode::kUnavailable,
                               HasSubstr("Cannot disable PQC")));
}

TEST(SslEcCurvesTest, GetPqcEcCurvesDefault) {
  ScopedEnvironment env("GOOGLE_CLOUD_CPP_DISABLE_PQC", std::nullopt);
  auto actual = GetPqcEcCurves();
  ASSERT_STATUS_OK(actual);
  EXPECT_THAT(*actual,
              AnyOf(IsEmpty(), Eq("X25519MLKEM768:X25519:P-256:P-384")));
}

TEST(SslEcCurvesTest, GetPqcEcCurvesDisabledViaEnv) {
  ScopedEnvironment env("GOOGLE_CLOUD_CPP_DISABLE_PQC", "true");
  auto actual = GetPqcEcCurves();
  if (actual.ok()) {
    EXPECT_EQ(*actual, "X25519:P-256:P-384");
    EXPECT_THAT(*actual, Not(HasSubstr("MLKEM")));
  } else {
    EXPECT_THAT(actual, StatusIs(StatusCode::kUnavailable));
  }
}

}  // namespace
GOOGLE_CLOUD_CPP_INLINE_NAMESPACE_END
}  // namespace rest_internal
}  // namespace cloud
}  // namespace google
