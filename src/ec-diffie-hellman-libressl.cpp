// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include <openssl/ec.h>
#include <openssl/err.h>

#include "libressl-helpers.h"
#include "ec-diffie-hellman-libressl.h"

ECDiffieHellmanLibreSSL::ECDiffieHellmanLibreSSL() {

}

ECDiffieHellmanLibreSSL::~ECDiffieHellmanLibreSSL() {

}

std::string_view ECDiffieHellmanLibreSSL::GetImplementationName() const {
  return "LibreSSL ECDH";
}

Result ECDiffieHellmanLibreSSL::GetSupportedCurves(
  std::map<std::string, CurveInfo>* curves) const {
  ERR_clear_error();
  size_t count = EC_get_builtin_curves(nullptr, 0);
  if (count <= 0) {
    return {Result::Fail,
      "Couldn't get built-in curve list: 0 count."};
  }

  auto buffer = std::make_unique<EC_builtin_curve[]>(count);
  if (EC_get_builtin_curves(buffer.get(), count) != count) {
    return {Result::Fail,
      "Couldn't get built-in curve list: EC_get_builtin_curves failed."};
  }

  for (int i = 0; i < count; ++i) {
    const char* shortName = OBJ_nid2sn(buffer[i].nid);
    const char* comment = buffer[i].comment;
    if (shortName && std::strlen(shortName) > 0) {
      curves->emplace(shortName,
        CurveInfo{buffer[i].nid, shortName, (comment) ? comment : ""});
    }
  }

  return {Result::Success};
}

Result ECDiffieHellmanLibreSSL::SetCurveName(std::string_view curveName) {
  std::map<std::string, CurveInfo> curves;
  Result result = GetSupportedCurves(&curves);
  if (!result) {
    return result;
  }

  auto it = curves.find(curveName.data());
  if (it == curves.end()) {
    return {Result::Fail, "The curve is not supported."};
  }

  curveName_ = (*it).second.name_;
  curveId_ = (*it).second.internalId_;

  return {Result::Success};
}

Result ECDiffieHellmanLibreSSL::GetCurveName(std::string* curveName) const {
  if (curveName_.empty()) {
    return {Result::Fail, "The curve name is not set."};
  }
  *curveName = curveName_;
  return {Result::Success};
}

Result ECDiffieHellmanLibreSSL::GenerateKeys() {
  ERR_clear_error();

  // Create the key parameter context.
  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    keyParamCtx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
  if (!keyParamCtx) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_CTX_new_id failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  // Initialize the key parameter context.
  if (EVP_PKEY_paramgen_init(keyParamCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_paramgen_init failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  // Set the curve name to the key parameter context.
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyParamCtx.get(), curveId_) <= 0) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed: {}",
      LibreSSL::GetLastErrorString()};
  }  

  // Generate key parameters.
  EVP_PKEY* keyParam = nullptr;
  if (EVP_PKEY_paramgen(keyParamCtx.get(), &keyParam) <= 0) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_paramgen failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  // keyParam auto free 
  std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>
    keyParamHolder(keyParam);

  // Create the key generation context.
  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    keyPairGenerationCtx{EVP_PKEY_CTX_new(keyParam, nullptr)};
  if (!keyPairGenerationCtx) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_CTX_new failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  // Initialize the key generation context.
  if (EVP_PKEY_keygen_init(keyPairGenerationCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_keygen_init failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  // Genearate keys.
  EVP_PKEY* keyPair = nullptr;
  if (EVP_PKEY_keygen(keyPairGenerationCtx.get(), &keyPair) <= 0) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_keygen failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  // Set the key pair.
  keyPair_.reset(keyPair);

  return {Result::Success};
}

Result ECDiffieHellmanLibreSSL::GetPrivateKey(std::string* hexPrivateKey) const {
  ERR_clear_error();

  const EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(keyPair_.get());
  if (!ecKey) {
    return {Result::Fail,
      "Couldn't get the private key: EVP_PKEY_get0_EC_KEY failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  const BIGNUM* privateKey = EC_KEY_get0_private_key(ecKey);
  if (!privateKey) {
    return {Result::Fail,
      "Couldn't get the private key: EVP_PKEY_get0_EC_KEY failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  *hexPrivateKey = LibreSSL::ConvertBigNumToHex(privateKey);
  return {Result::Success};
}

Result ECDiffieHellmanLibreSSL::GetPublicKey(std::string* hexPublicKey) const {
  ERR_clear_error();

  const EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(keyPair_.get());
  if (!ecKey) {
    return {Result::Fail,
      "Couldn't get the public key: EVP_PKEY_get0_EC_KEY failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);

  std::unique_ptr<char, Base::DeleterFromFn<CRYPTO_free>> hexECPoint{
    EC_POINT_point2hex(ecGroup, EC_KEY_get0_public_key(ecKey),
      POINT_CONVERSION_COMPRESSED, nullptr) };
  if (!hexECPoint) {
    return {Result::Fail,
       "Couldn't get the public key: EC_POINT_point2hex failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  *hexPublicKey = hexECPoint.get();
  return {Result::Success};
}

Result ECDiffieHellmanLibreSSL::DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const {
  ERR_clear_error();

  const EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(curveId_);

  std::unique_ptr<EC_POINT, Base::DeleterFromFn<EC_POINT_free>>    
    peerPublicECPoint{EC_POINT_hex2point(ecGroup,
      hexPeerPublicKey.data(), nullptr, nullptr)};
  if (!peerPublicECPoint) {
    return {Result::Fail,
       "Couldn't derive: EC_POINT_hex2point failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  std::unique_ptr<EC_KEY, Base::DeleterFromFn<EC_KEY_free>>
    peerPublicECKey{EC_KEY_new_by_curve_name(curveId_)};
  if (!peerPublicECKey) {
    return {Result::Fail,
       "Couldn't derive: EC_KEY_new_by_curve_name failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  if (!EC_KEY_set_public_key(peerPublicECKey.get(), peerPublicECPoint.get())) {
    return {Result::Fail,
       "Couldn't derive: EC_KEY_set_public_key failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>
    peerPublicKey{EVP_PKEY_new()};
  if (!peerPublicKey) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_new failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  if (!EVP_PKEY_set1_EC_KEY(peerPublicKey.get(), peerPublicECKey.get())) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_set1_EC_KEY failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    derivationCtx{EVP_PKEY_CTX_new(keyPair_.get(), nullptr) };
  if (!derivationCtx) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_CTX_new failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_derive_init(derivationCtx.get()) <= 0) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_derive_init failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  if (EVP_PKEY_derive_set_peer(derivationCtx.get(), peerPublicKey.get()) <= 0) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_derive_set_peer failed: {}",
       LibreSSL::GetLastErrorString()};
  }

  size_t sharedSecretLen = 0;
  if (EVP_PKEY_derive(derivationCtx.get(), nullptr, &sharedSecretLen) <= 0) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_derive returned zero shared secret length: {}",
       LibreSSL::GetLastErrorString()};
  }

  // Prepare the shared secret container.
  std::string sharedSecret;
  sharedSecret.resize(sharedSecretLen);

  // Derive the shared secret.
  if (EVP_PKEY_derive(derivationCtx.get(),
      static_cast<unsigned char*>(static_cast<void*>(&sharedSecret.front())),
      &sharedSecretLen) <= 0) {
    return {Result::Fail,
       "Couldn't derive: EVP_PKEY_derive failed: {}",
       LibreSSL::GetLastErrorString()};  
  }

  // Convert to a hex string.
  *hexSharedSecret = Base::ConvertDataToHex(sharedSecret);

  return {Result::Success};
}
