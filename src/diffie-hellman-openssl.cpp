// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <format>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

#include "base-helpers.h"
#include "openssl-helpers.h"
#include "diffie-hellman-openssl.h"

DiffieHellmanOpenSSL::DiffieHellmanOpenSSL() {
}

DiffieHellmanOpenSSL::~DiffieHellmanOpenSSL() {

}

std::string_view DiffieHellmanOpenSSL::GetImplementaionName() const {
  return "openssl";
}

Result DiffieHellmanOpenSSL::GenerateParameters(int primeLengthInBits, int generator) {
  ERR_clear_error();

  if (generator <= 1) {
    return {Result::Fail, "Couldn't generate params: bad generator value."};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> bigAdd{BN_new()};
  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> bigRem{BN_new()};
  if (!bigAdd || !bigRem) {
    return {Result::Fail, "Couldn't generate params: BN_CTX_get failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (generator == DH_GENERATOR_2) {
    if (!BN_set_word(bigAdd.get(), 24) || !BN_set_word(bigRem.get(), 23)) {
      return {Result::Fail, "Couldn't generate params: BN_set_word failed: {}",
        OpenSSL::GetLastErrorString()};
    }
  } else if (generator == DH_GENERATOR_5) {
    if (!BN_set_word(bigAdd.get(), 60) || !BN_set_word(bigRem.get(), 59)) {
      return {Result::Fail, "Couldn't generate params: BN_set_word failed: {}",
        OpenSSL::GetLastErrorString()};
    }
  } else {
    if (!BN_set_word(bigAdd.get(), 12) || !BN_set_word(bigRem.get(), 11)) {
      return {Result::Fail, "Couldn't generate params: BN_set_word failed: {}",
        OpenSSL::GetLastErrorString()};
    }
  }

  prime_.reset(BN_new());
  if (!prime_) {
    return {Result::Fail, "Couldn't generate params: prime BN_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  generator_.reset(BN_new());
  if (!generator_) {
    return {Result::Fail, "Couldn't generate params: generator BN_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (!BN_generate_prime_ex(prime_.get(), primeLengthInBits, 1,
      bigAdd.get(), bigRem.get(), nullptr)) {
    return {Result::Fail,
      "Couldn't generate params: generator BN_generate_prime_ex failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (!BN_set_word(generator_.get(), static_cast<BN_ULONG>(generator))) {
    return {Result::Fail,
      "Couldn't generate params: generator BN_set_word(genrator): {}",
      OpenSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::SetParameters(std::string_view hexPrime, std::string_view hexGenerator) {
  ERR_clear_error();

  prime_.reset(OpenSSL::ConvertHexToBigNum(hexPrime));
  if (!prime_) {
    return {Result::Fail,
      "Couldn't set params: ConvertHexToBigNum(hexPrime) failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  generator_.reset(OpenSSL::ConvertHexToBigNum(hexGenerator));
  if (!generator_) {
    return {Result::Fail,
      "Couldn't set params: ConvertHexToBigNum(hexGenerator) failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::GetParameters(std::string* hexPrime, std::string* hexGenerator) const {
  ERR_clear_error();

  *hexPrime = OpenSSL::ConvertBigNumToHex(prime_.get());
  if (hexPrime->empty()) {
    return {Result::Fail,
      "Couldn't get params: ConvertBigNumToHex(prime) failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  *hexGenerator = OpenSSL::ConvertBigNumToHex(generator_.get());
  if (hexGenerator->empty()) {
    return {Result::Fail,
      "Couldn't get params: ConvertBigNumToHex(generator) failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::GenerateKeys() {
  ERR_clear_error();

  std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>> domainParamKey;
  Result result = CreateDomainParameterKey(&domainParamKey);
  if (!result) {
    return result;
  }

  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>> keyGenCtx{
    EVP_PKEY_CTX_new_from_pkey(nullptr, domainParamKey.get(), nullptr)};
  if (!keyGenCtx) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_CTX_new_from_pkey failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_keygen_init(keyGenCtx.get()) <= 0) {
    return {Result::Fail, "Couldn't generate: EVP_PKEY_keygen_init failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  EVP_PKEY* keyPair = nullptr;
  if (EVP_PKEY_generate(keyGenCtx.get(), &keyPair) <= 0) {
    return {Result::Fail, "Couldn't generate: EVP_PKEY_generate failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  keyPair_.reset(keyPair);

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::GetPrivateKey(std::string* hexPrivateKey) const {
  ERR_clear_error();

  BIGNUM* privateKey = nullptr;
  if (!EVP_PKEY_get_bn_param(keyPair_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &privateKey)) {
    return {Result::Fail,
      "Could not get the private key: EVP_PKEY_get_bn_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> privateKeyHolder{privateKey};

  *hexPrivateKey = OpenSSL::ConvertBigNumToHex(privateKey);
  if (hexPrivateKey->empty()) {
    return {Result::Fail,
      "Could not get the private key: ConvertBigNumToHex failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::GetPublicKey(std::string* hexPublicKey) const {
  ERR_clear_error();

  BIGNUM* publicKey = nullptr;
  if (!EVP_PKEY_get_bn_param(keyPair_.get(), OSSL_PKEY_PARAM_PUB_KEY, &publicKey)) {
    return {Result::Fail,
      "Could not get the public key: EVP_PKEY_get_bn_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> publicKeyHolder{publicKey};

  *hexPublicKey = OpenSSL::ConvertBigNumToHex(publicKey);
  if (hexPublicKey->empty()) {
    return {Result::Fail,
      "Could not get the public key: ConvertBigNumToHex failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const {
  ERR_clear_error();

  std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>> peerPublicKey;
  Result result = CreatePeerPublicKey(hexPeerPublicKey, &peerPublicKey);
  if (!result) {
    return result;
  }  

  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    derivationCtx{EVP_PKEY_CTX_new(keyPair_.get(), nullptr)};
  if (!derivationCtx) {
    return {Result::Fail,
      "Couldn't derive: EVP_PKEY_CTX_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_derive_init(derivationCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't derive: EVP_PKEY_derive_init failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_derive_set_peer(derivationCtx.get(), peerPublicKey.get()) <= 0) {
    return {Result::Fail,
      "Couldn't derive: EVP_PKEY_derive_set_peer failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  size_t len = 0;
  if (EVP_PKEY_derive(derivationCtx.get(), nullptr, &len) <= 0) {
    return {Result::Fail,
      "Couldn't derive: EVP_PKEY_derive: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (len == 0) {
    return {Result::Fail, "Couldn't derive: share secret length is zero."};
  }

  std::string sharedSecret;
  sharedSecret.resize(len);

  if (EVP_PKEY_derive(derivationCtx.get(),
      static_cast<unsigned char*>(static_cast<void*>(&sharedSecret.front())),
      &len) <= 0) {
    return {Result::Fail,
      "Couldn't derive: EVP_PKEY_derive failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  *hexSharedSecret = Base::ConvertDataToHex(sharedSecret);

  return {Result::Success};
}

std::tuple<int, int> DiffieHellmanOpenSSL::GetPrimeLength() const {
  if (!prime_) {
    return {-1, -1};
  }
  return {BN_num_bits(prime_.get()), BN_num_bytes(prime_.get())};
}

std::tuple<int, int> DiffieHellmanOpenSSL::GetPrivateKeyLength() const {
  BIGNUM* privateKey = nullptr;
  if (!EVP_PKEY_get_bn_param(keyPair_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &privateKey)) {
    return {-1, -1};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> privateKeyHolder{privateKey};
  return {BN_num_bits(privateKey), BN_num_bytes(privateKey)};
}

std::tuple<int, int> DiffieHellmanOpenSSL::GetPublicKeyLength() const {
  BIGNUM* publicKey = nullptr;
  if (!EVP_PKEY_get_bn_param(keyPair_.get(), OSSL_PKEY_PARAM_PUB_KEY, &publicKey)) {
    return {-1, -1};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> publicKeyHolder{publicKey};
  return {BN_num_bits(publicKey), BN_num_bytes(publicKey)};
}

Result DiffieHellmanOpenSSL::CreatePeerPublicKey(std::string_view hexPeerPublicKey,
    std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>* peerPubKey) const {
  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>>
    bigNumPeerPublicKey{OpenSSL::ConvertHexToBigNum(hexPeerPublicKey)};
  if (!bigNumPeerPublicKey) {
    return {Result::Fail,
      "Couldn't create the peer public key: ConvertHexToBigNum failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<OSSL_PARAM_BLD, Base::DeleterFromFn<OSSL_PARAM_BLD_free>>
    paramBuild{OSSL_PARAM_BLD_new()};
  if (!paramBuild) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (!OSSL_PARAM_BLD_push_BN(paramBuild.get(),
      OSSL_PKEY_PARAM_PUB_KEY, bigNumPeerPublicKey.get())) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_push_BN(pub key) failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (!OSSL_PARAM_BLD_push_BN(paramBuild.get(), OSSL_PKEY_PARAM_FFC_P, prime_.get()) ||
      !OSSL_PARAM_BLD_push_BN(paramBuild.get(), OSSL_PKEY_PARAM_FFC_G, generator_.get())) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_push_BN(p or g) failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<OSSL_PARAM, Base::DeleterFromFn<OSSL_PARAM_free>>
    param{OSSL_PARAM_BLD_to_param(paramBuild.get())};
  if (!param) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_to_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    peerPublicKeyCtx{EVP_PKEY_CTX_new_from_name(nullptr, "DHX", nullptr)};
  if (!peerPublicKeyCtx) {
    return {Result::Fail,
      "Couldn't create the peer public key: EVP_PKEY_CTX_new_from_name failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_fromdata_init(peerPublicKeyCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't create the peer public key: EVP_PKEY_fromdata_init failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  EVP_PKEY* tmp = nullptr;
  if (EVP_PKEY_fromdata(peerPublicKeyCtx.get(), &tmp,
      EVP_PKEY_PUBLIC_KEY, param.get()) <= 0) {
    return {Result::Fail,
      "Couldn't create the peer public key: EVP_PKEY_fromdata failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  peerPubKey->reset(tmp);

  return {Result::Success};
}

Result DiffieHellmanOpenSSL::CreateDomainParameterKey(
  std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>* domainParamKey) const
{
  std::unique_ptr<OSSL_PARAM_BLD, Base::DeleterFromFn<OSSL_PARAM_BLD_free>> paramBuild{
    OSSL_PARAM_BLD_new()};
  if (!paramBuild) {
    return {Result::Fail,
      "Couldn't create the domain param key: OSSL_PARAM_BLD_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (!OSSL_PARAM_BLD_push_BN(paramBuild.get(), OSSL_PKEY_PARAM_FFC_P, prime_.get()) ||
    !OSSL_PARAM_BLD_push_BN(paramBuild.get(), OSSL_PKEY_PARAM_FFC_G, generator_.get())) {
    return {Result::Fail,
      "Couldn't create the domain param key: OSSL_PARAM_BLD_push_BN failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<OSSL_PARAM, Base::DeleterFromFn<OSSL_PARAM_free>>
    param{OSSL_PARAM_BLD_to_param(paramBuild.get())};
  if (!param) {
    return {Result::Fail,
      "Couldn't create the domain param key: OSSL_PARAM_BLD_to_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    domainParamKeyCtx{EVP_PKEY_CTX_new_from_name(nullptr, "DHX", nullptr)};
  if (!domainParamKeyCtx) {
    return {Result::Fail,
      "Couldn't create the domain param key: EVP_PKEY_CTX_new_from_name failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_fromdata_init(domainParamKeyCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't create the domain param key: EVP_PKEY_fromdata_init failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  EVP_PKEY* tmp = nullptr;
  if (EVP_PKEY_fromdata(domainParamKeyCtx.get(), &tmp,
      EVP_PKEY_KEY_PARAMETERS, param.get()) <= 0) {
    return {Result::Fail,
      "Couldn't create the domain param key: EVP_PKEY_fromdata failed: {}",
      OpenSSL::GetLastErrorString()};
  }
 
  domainParamKey->reset(tmp);

  return {Result::Success};

}