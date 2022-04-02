// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <memory>
#include <string_view>

#include "base-helpers.h"
#include "ec-diffie-hellman.h"

#include <openssl/evp.h>

// Elliptic-curve Diffie-Hellman implementation based on OpenSSL 3.x.x.
class ECDiffieHellmanOpenSSL : public ECDiffieHellman {
 public:
  ECDiffieHellmanOpenSSL();
  ~ECDiffieHellmanOpenSSL() override;

  std::string_view GetImplementationName() const override;

  Result GetSupportedCurves(std::map<std::string,
    CurveInfo>* curves) const override;

  Result SetCurveName(std::string_view curveName) override;
  Result GetCurveName(std::string* curveName) const override;

  Result GenerateKeys() override;
  Result GetPrivateKey(std::string* hexPrivateKey) const override; // for debug
  Result GetPublicKey(std::string* hexPublicKey) const override;

  Result DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const override;

 private:
   Result CreatePeerPublicKey(std::string_view hexPeerPublicKey,
     std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>* peerPublicKey) const;

   std::string curveName_;
   std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>> keyPair_;
};
