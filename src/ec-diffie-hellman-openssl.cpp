// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

#include "openssl-helpers.h"
#include "ec-diffie-hellman-openssl.h"

ECDiffieHellmanOpenSSL::ECDiffieHellmanOpenSSL() {

}

ECDiffieHellmanOpenSSL::~ECDiffieHellmanOpenSSL() {
  
}

std::string_view ECDiffieHellmanOpenSSL::GetImplementationName() const {
  return "OpenSSL ECDH";
}

Result ECDiffieHellmanOpenSSL::GetSupportedCurves(
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

Result ECDiffieHellmanOpenSSL::SetCurveName(std::string_view curveName) {
  std::map<std::string, CurveInfo> curves;
  Result result = GetSupportedCurves(&curves);
  if (!result) {
    return result;
  }

  // Check if the curve is in the list.
  if (!curves.count(curveName.data())) {
   return {Result::Fail, "The curve is not supported."};
  }

  curveName_ = curveName;
  return {Result::Success};
}

Result ECDiffieHellmanOpenSSL::GetCurveName(std::string* curveName) const {
  if (curveName_.empty()) {
    return {Result::Fail, "The curve name is not set."};
  }
  *curveName = curveName_;
  return {Result::Success};
}

Result ECDiffieHellmanOpenSSL::GenerateKeys() {
  ERR_clear_error();

  // First, create an OSSL_PARAM_BLD.
  std::unique_ptr<OSSL_PARAM_BLD, Base::DeleterFromFn<OSSL_PARAM_BLD_free>>
    paramBuild{OSSL_PARAM_BLD_new()};
  if (!paramBuild) {
    return {Result::Fail,
      "Couldn't generate: OSSL_PARAM_BLD_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Push the curve name to the OSSL_PARAM_BLD.
  if (!OSSL_PARAM_BLD_push_utf8_string(paramBuild.get(),
      OSSL_PKEY_PARAM_GROUP_NAME, curveName_.data(), 0)) {
    return {Result::Fail,
      "Couldn't generate: OSSL_PARAM_BLD_push_utf8_string failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Convert OSSL_PARAM_BLD to OSSL_PARAM.
  std::unique_ptr<OSSL_PARAM, Base::DeleterFromFn<OSSL_PARAM_free>>
    params{OSSL_PARAM_BLD_to_param(paramBuild.get())};
  if (!params) {
    return {Result::Fail,
      "Couldn't generate: OSSL_PARAM_BLD_to_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Create the EC key generation context.
  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
  if (!ctx) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_CTX_new_from_name failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Initialize the key generation context.
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't generate: EVP_PKEY_keygen_init failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Set the parameters which include the curve name.
  if (!EVP_PKEY_CTX_set_params(ctx.get(), params.get())) {
    return {Result::Fail,
     "Couldn't generate: EVP_PKEY_CTX_set_params failed: {}",
     OpenSSL::GetLastErrorString()};
  }

  // Generate a key pair.
  EVP_PKEY* keyPair = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &keyPair) <= 0) {
     return {Result::Fail,
       "Couldn't generate: EVP_PKEY_generate failed: {}",
      OpenSSL::GetLastErrorString()};   
  }

  keyPair_.reset(keyPair);

  return {Result::Success};
}

Result ECDiffieHellmanOpenSSL::GetPrivateKey(std::string* hexPrivateKey) const {
  ERR_clear_error();

  // The private key is stored as a BIGNUM object.
  BIGNUM* privateKey = nullptr;
  if (!EVP_PKEY_get_bn_param(keyPair_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &privateKey)) {
    return {Result::Fail,
      "Could not get the private key: EVP_PKEY_get_bn_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> privateKeyHolder{privateKey};

  // Convert the BIGNUM to a hex string.
  *hexPrivateKey = OpenSSL::ConvertBigNumToHex(privateKey);
  if (hexPrivateKey->empty()) {
    return {Result::Fail,
      "Could not get the private key: ConvertBigNumToHex failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result ECDiffieHellmanOpenSSL::GetPublicKey(std::string* hexPublicKey) const {
  ERR_clear_error();

  // The public key is stored as a byte array.
  // Get the array size.
  size_t keyLength = 0;
  if (!EVP_PKEY_get_octet_string_param(keyPair_.get(), OSSL_PKEY_PARAM_PUB_KEY,
    nullptr, 0, &keyLength)) {
    return {Result::Fail,
      "Couldn't get the public key length: EVP_PKEY_get_octet_string_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Get the key.
  auto publicKey = std::make_unique<std::uint8_t[]>(keyLength);
  if (!EVP_PKEY_get_octet_string_param(keyPair_.get(), OSSL_PKEY_PARAM_PUB_KEY,
    publicKey.get(), keyLength, &keyLength)) {
    return {Result::Fail,
      "Couldn't get the public key: EVP_PKEY_get_octet_string_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Convert the byte array key to a hex string.
  *hexPublicKey = Base::ConvertDataToHex(
    std::string_view(static_cast<char*>(
      static_cast<void*>(publicKey.get())), keyLength));
  return {Result::Success};
}

Result ECDiffieHellmanOpenSSL::DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const {
  ERR_clear_error();
  Result result;

  // First, you have to create the peer public key object.
  // It takes several calls, so it is done in a separate function.
  std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>> peerPublicKey;
  result = CreatePeerPublicKey(hexPeerPublicKey, &peerPublicKey);
  if (!result) {
    return result;
  }

  // Create the derivation context.
  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    derivationCtx{EVP_PKEY_CTX_new(keyPair_.get(), nullptr)};
  if (!derivationCtx) {
    return {Result::Fail,
     "Couldn't derive the shared secret: EVP_PKEY_CTX_new failed: {}",
     OpenSSL::GetLastErrorString()};
  }

  // Initialize the derivation context.
  if (EVP_PKEY_derive_init(derivationCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't derive the shared secret: EVP_PKEY_derive_init failed: {}",
      OpenSSL::GetLastErrorString()};   
  }

  // Set the peer public key object.
  if (EVP_PKEY_derive_set_peer(derivationCtx.get(), peerPublicKey.get()) <= 0) {
    return {Result::Fail,
      "Couldn't derive the shared secret: EVP_PKEY_derive_set_peer failed: {}",
      OpenSSL::GetLastErrorString()};   
  }

  // Get the shared secret length.
  size_t sharedSecretLength = 0;
  if (EVP_PKEY_derive(derivationCtx.get(), nullptr, &sharedSecretLength) <= 0) {
     return {Result::Fail,
      "Couldn't derive the shared secret: EVP_PKEY_derive failed: {}",
      OpenSSL::GetLastErrorString()};   
  }

  if (sharedSecretLength == 0) {
    return {Result::Fail,
      "Couldn't derive the shared secret: zero length shared secret."};
  }

  
  std::string sharedSecret;
  sharedSecret.resize(sharedSecretLength);

  // Derive the shared secret.
  if (EVP_PKEY_derive(derivationCtx.get(),
      static_cast<unsigned char*>(static_cast<void*>(
        &sharedSecret.front())), &sharedSecretLength) <= 0) {
     return {Result::Fail,
      "Couldn't derive the shared secret: EVP_PKEY_derive failed: {}",
      OpenSSL::GetLastErrorString()};    
  }

  // Convert to a hex string.
  *hexSharedSecret = Base::ConvertDataToHex(sharedSecret);

  return {Result::Success};
}

Result ECDiffieHellmanOpenSSL::CreatePeerPublicKey(std::string_view hexPeerPublicKey,
    std::unique_ptr<EVP_PKEY, Base::DeleterFromFn<EVP_PKEY_free>>* peerPublicKey) const {
  Result result;

  // First, we sould create an OSSL_PARAM_BLD with the curve name
  // and the raw peer public key.
  std::unique_ptr<OSSL_PARAM_BLD, Base::DeleterFromFn<OSSL_PARAM_BLD_free>>
    paramBuild{OSSL_PARAM_BLD_new()};
  if (!paramBuild) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Set the curve name.
  if (!OSSL_PARAM_BLD_push_utf8_string(paramBuild.get(), OSSL_PKEY_PARAM_GROUP_NAME,
      curveName_.data(), 0)) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_new failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Convert the peer hex public key to raw data.
  std::string binPeerPublicKey;
  result = Base::ConvertHexToData(hexPeerPublicKey, &binPeerPublicKey);
  if (!result) {
    return result;
  }

  // Set the raw peer public key.
  if (!OSSL_PARAM_BLD_push_octet_string(paramBuild.get(), OSSL_PKEY_PARAM_PUB_KEY,
    binPeerPublicKey.data(), binPeerPublicKey.size())) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_push_octet_string failed: {}",
      OpenSSL::GetLastErrorString()};   
  }

  // Convert the OSSL_PARAM_BLD to OSSL_PARAM.
  std::unique_ptr<OSSL_PARAM, Base::DeleterFromFn<OSSL_PARAM_free>>
    params{OSSL_PARAM_BLD_to_param(paramBuild.get())};
  if (!params) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_to_param failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Create a EVP_PKEY context.
  std::unique_ptr<EVP_PKEY_CTX, Base::DeleterFromFn<EVP_PKEY_CTX_free>>
    peerPublicKeyCtx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
  if (!peerPublicKeyCtx) {
    return {Result::Fail,
      "Couldn't create the peer public key: OSSL_PARAM_BLD_to_param failed: {}",
      OpenSSL::GetLastErrorString()};    
  }

  // Initialize the context.
  if (EVP_PKEY_fromdata_init(peerPublicKeyCtx.get()) <= 0) {
    return {Result::Fail,
      "Couldn't create the peer public key: EVP_PKEY_fromdata_init failed: {}",
      OpenSSL::GetLastErrorString()};
  }

  // Create the peer public key object.
  EVP_PKEY* tmp = nullptr;
  if (EVP_PKEY_fromdata(peerPublicKeyCtx.get(), &tmp, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
    return {Result::Fail,
      "Couldn't create the peer public key: EVP_PKEY_fromdata failed: {}",
      OpenSSL::GetLastErrorString()};    
  }

  peerPublicKey->reset(tmp);

  return {Result::Success};
}
