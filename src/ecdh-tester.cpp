// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chrono>
#include <iostream>
#include <format>
#include <vector>

#include "result.h"
#include "base-helpers.h"
#include "ec-diffie-hellman.h"

#include "ecdh-tester.h"

ECDHTester::ECDHTester(std::string_view curveName)
  : curveName_(curveName.data()) {
}

void ECDHTester::Run() {

  std::cout << "--------------------------------------------------------" << std::endl;
  std::cout << "CURVE NAME: " << curveName_ << std::endl;

  using Impl = ECDiffieHellman::Implementation;

  std::vector<std::pair<Impl, Impl>> tests = {
    {Impl::OpenSSL, Impl::OpenSSL},
    {Impl::LibreSSL, Impl::LibreSSL},
  };

  for (const auto& test : tests) {
    auto alice = ECDiffieHellman::Create(test.first);
    auto bob = ECDiffieHellman::Create(test.second);
    if (alice && bob) {
      std::cout << "--------------------------------------------------------" << std::endl;

      std::string testDescription = std::format("ALICE {} <-> BOB {}",
        alice->GetImplementationName(), bob->GetImplementationName());
      std::cout << testDescription << std::endl;

      auto result = DoTest(alice.get(), bob.get());

      std::string resultDescription = (result) ? "success" : result.GetDescription();
      std::cout << "RESULT: " << resultDescription << std::endl << std::endl;
    }
  }
}

Result ECDHTester::DoTest(ECDiffieHellman* alice, ECDiffieHellman* bob) {
  Result result;

  // Alice initialization.

  if (!(result = alice->SetCurveName(curveName_))) {
    return result;
  }

  if (!(result = alice->GenerateKeys())) {
    return result;
  }

  std::string aliceHexPublicKey;
  if (!(result = alice->GetPublicKey(&aliceHexPublicKey))) {
    return result;
  }

  std::cout << "ALICE public key length (hex digits): " << aliceHexPublicKey.size() << std::endl;
  std::cout << "ALICE public key: " << aliceHexPublicKey << std::endl;
  
  std::string aliceHexPrivateKey;
  if (!(result = alice->GetPrivateKey(&aliceHexPrivateKey))) {
    return result;
  }

  std::cout << "ALICE private key: " << aliceHexPrivateKey << std::endl;

  // Bob initialization.

  if (!(result = bob->SetCurveName(curveName_))) {
    return result;
  }

  if (!(result = bob->GenerateKeys())) {
    return result;
  }

  std::string bobHexPublicKey;
  if (!(result = bob->GetPublicKey(&bobHexPublicKey))) {
    return result;
  }

  std::cout << "BOB public key length (hex digits): " << bobHexPublicKey.size() << std::endl;
  std::cout << "BOB public key: " << bobHexPublicKey << std::endl;

  std::string bobHexPrivateKey;
  if (!(result = bob->GetPrivateKey(&bobHexPrivateKey))) {
    return result;
  }
  
  std::cout << "BOB private key: " << bobHexPrivateKey << std::endl;

  // Derivation

  std::string aliceHexSharedSecret;
  if (!(result = alice->DeriveSharedSecret(bobHexPublicKey, &aliceHexSharedSecret))) {
    return result;
  }

  std::cout << "ALICE shared secret: " << aliceHexSharedSecret << std::endl;

  std::string bobHexSharedSecret;
  if (!(result = bob->DeriveSharedSecret(aliceHexPublicKey, &bobHexSharedSecret))) {
    return result;
  }

  std::cout << "BOB shared secret: " << bobHexSharedSecret << std::endl;

  if (aliceHexSharedSecret != bobHexSharedSecret) {
    return {Result::Fail, "The shared secrets are different!"};
  }

  return {Result::Success};
}

void ECDHTester::ShowSupportedCurves() {
  std::cout << "--------------------------------------------------------" << std::endl;

  // The project does not have a custom ECDH implementation
  // to test vs OpenSSL or LibreSSL, so we just enumerate
  // supported curves of OpenSSL or LIbreSSL.
#if defined(USE_OPENSSL)
  auto ecdh = ECDiffieHellman::Create(ECDiffieHellman::Implementation::OpenSSL);
#else
  auto ecdh = ECDiffieHellman::Create(ECDiffieHellman::Implementation::LibreSSL);
#endif
  std::map<std::string, ECDiffieHellman::CurveInfo> curves;
  Result result = ecdh->GetSupportedCurves(&curves);
  if (result) {
    PrintCurvesInfo(curves);
  }
}

void ECDHTester::PrintCurvesInfo(const std::map<std::string, ECDiffieHellman::CurveInfo>& curves) {
  for (const auto& [curveName, curveInfo] : curves) {
    PrintCurveInfo(curveInfo);
  }
}

void ECDHTester::PrintCurveInfo(const ECDiffieHellman::CurveInfo& curveInfo) {
  std::cout << std::left << std::setw(32) << curveInfo.name_ << curveInfo.comment_ << std::endl;
}