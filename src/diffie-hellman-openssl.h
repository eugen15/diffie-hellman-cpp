// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <memory>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "result.h"
#include "openssl-helpers.h"
#include "diffie-hellman.h"

// Diffie-Hellman implementation based on OpenSSL 3.x.x.
class DiffieHellmanOpenSSL : public DiffieHellman {
 public:
  DiffieHellmanOpenSSL();
  ~DiffieHellmanOpenSSL() override;
  
  std::string_view GetImplementaionName() const override;

  Result GenerateParameters(int primeLengthInBits, int generator) override;

  Result SetParameters(std::string_view hexPrime, std::string_view hexGenerator) override;
  Result GetParameters(std::string* hexPrime, std::string* hexGenerator) const override;

  Result GenerateKeys() override;
  Result GetPrivateKey(std::string* hexPrivateKey) const override;
  Result GetPublicKey(std::string* hexPublicKey) const override;

  Result DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const override;

  std::tuple<int, int> GetPrimeLength() const override;
  std::tuple<int, int> GetPrivateKeyLength() const override;
  std::tuple<int, int> GetPublicKeyLength() const override;

 private:

   Result CreatePeerPublicKey(std::string_view hexPeerPublicKey,
     std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>* peerPubKey) const;

   Result CreateDomainParameterKey(
     std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>* domainParamKey) const;

   std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> prime_;
   std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> generator_;
   std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>> keyPair_;
};
