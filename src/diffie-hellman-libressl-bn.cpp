// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <format>

#include <openssl/err.h>
#include <openssl/crypto.h>

#include "base-helpers.h"
#include "diffie-hellman-libressl-bn.h"

DiffieHellmanLibreSSLBN::DiffieHellmanLibreSSLBN() {
}

DiffieHellmanLibreSSLBN::~DiffieHellmanLibreSSLBN() {
}

std::string_view DiffieHellmanLibreSSLBN::GetImplementaionName() const {
  return "libressl BIGNUM";
}

Result DiffieHellmanLibreSSLBN::GenerateParameters(int primeLengthInBits, int generator) {
  ERR_clear_error();

  if (generator <= 1) {
    return {Result::Fail, "Bad generator value."};
  }

  std::unique_ptr<BN_CTX, Base::DeleterFromFn<BN_CTX_free>> ctx{BN_CTX_new()};
  if (!ctx) {
    return {Result::Fail, "Could not create the big number context: {}",
      LibreSSL::GetLastErrorString()};
  }

  BN_CTX_start(ctx.get());

  BIGNUM* bigAdd{BN_CTX_get(ctx.get())};
  BIGNUM* bigRem{BN_CTX_get(ctx.get())};
  if (!bigAdd || !bigRem) {
    return {Result::Fail, "BN_CTX_get failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (generator == DH_GENERATOR_2) {
    if (!BN_set_word(bigAdd, 24) || !BN_set_word(bigRem, 11)) {
      return {Result::Fail, "BN_set_word failed: {}",
        LibreSSL::GetLastErrorString()};
    }
  } else if (generator == DH_GENERATOR_5) {
    if (!BN_set_word(bigAdd, 10) || !BN_set_word(bigRem, 3)) {
      return {Result::Fail, "BN_set_word failed: {}",
        LibreSSL::GetLastErrorString()};
    }
  } else {
    if (!BN_set_word(bigAdd, 2) || !BN_set_word(bigRem, 1)) {
      return {Result::Fail, "BN_set_word failed: {}",
        LibreSSL::GetLastErrorString()};
    }
  }

  prime_.reset(BN_new());
  if (!prime_) {
    return {Result::Fail, "Could not create the prime: {}",
      LibreSSL::GetLastErrorString()};
  }

  generator_.reset(BN_new());
  if (!generator_) {
    return {Result::Fail, "Could not create the generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (!BN_generate_prime_ex(prime_.get(), primeLengthInBits, 1, bigAdd, bigRem, nullptr)) {
    return {Result::Fail, "BN_generate_prime_ex failed: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (!BN_set_word(generator_.get(), static_cast<BN_ULONG>(generator))) {
    return {Result::Fail, "Could not set the generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  BN_CTX_end(ctx.get());

  return {Result::Success};
}

Result DiffieHellmanLibreSSLBN::SetParameters(std::string_view hexPrime,
    std::string_view hexGenerator) {
  ERR_clear_error();

  prime_.reset(LibreSSL::ConvertHexToBigNum(hexPrime));
  if (!prime_) {
    return {Result::Fail, "Could not convert the hex data to the prime: {}",
      LibreSSL::GetLastErrorString()};
  }

  generator_.reset(LibreSSL::ConvertHexToBigNum(hexGenerator));
  if (!generator_) {
    return {Result::Fail, "Could not convert the hex data to the generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  return {Result::Success};
}
Result DiffieHellmanLibreSSLBN::GetParameters(std::string* hexPrime,
    std::string* hexGenerator) const {
  ERR_clear_error();

  hexPrime->clear();
  hexPrime->append(LibreSSL::ConvertBigNumToHex(prime_.get()));
  if (hexPrime->empty()) {
    return {Result::Fail, "Could not get prime: {}",
      LibreSSL::GetLastErrorString()};
  }

  hexGenerator->clear();
  hexGenerator->append(LibreSSL::ConvertBigNumToHex(generator_.get()));
  if (hexGenerator->empty()) {
    return {Result::Fail, "Could not get generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLBN::GenerateKeys() {
  ERR_clear_error();

  if (BN_num_bits(prime_.get()) > OPENSSL_DH_MAX_MODULUS_BITS) {
    return {Result::Fail, "Modulus too large."};
  }

  std::unique_ptr<BN_CTX, Base::DeleterFromFn<BN_CTX_free>> ctx{BN_CTX_new()};
  if (!ctx) {
    return {Result::Fail, "Could not create the big number context: {}",
      LibreSSL::GetLastErrorString()};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> privateKey{BN_new()};
  if (!privateKey) {
    return {Result::Fail, "Could not create the private key: {}",
      LibreSSL::GetLastErrorString()};
  }
  
  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> publicKey{BN_new()};
  if (!publicKey) {
    return {Result::Fail, "Could not create the public key: {}",
      LibreSSL::GetLastErrorString()};
  }

  unsigned int len = BN_num_bits(prime_.get()) - 1;
  if (!BN_rand(privateKey.get(), len, 0, 0)) {
    return {Result::Fail, "Could not generate the private key: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (!BN_mod_exp(publicKey.get(), generator_.get(), privateKey.get(), prime_.get(), ctx.get())) {
    return {Result::Fail, "Could not derive the public key from the private key: {}",
      LibreSSL::GetLastErrorString()};
  }

  publicKey_ = std::move(publicKey);
  privateKey_ = std::move(privateKey);

  return {Result::Success};
}

Result DiffieHellmanLibreSSLBN::GetPrivateKey(std::string* hexPrivateKey) const {
  ERR_clear_error();

  hexPrivateKey->clear();
  hexPrivateKey->append(LibreSSL::ConvertBigNumToHex(privateKey_.get()));
  if (hexPrivateKey->empty()) {
    return {Result::Fail, "The private key is empty."};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLBN::GetPublicKey(std::string* hexPublicKey) const {
  ERR_clear_error();

  hexPublicKey->clear();
  hexPublicKey->append(LibreSSL::ConvertBigNumToHex(publicKey_.get()));
  if (hexPublicKey->empty()) {
    return {Result::Fail, "The public key is empty."};
  }

  return {Result::Success};
}

static Result CheckPublicKey(BIGNUM* p, BIGNUM* publicKey) {
  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> q(BN_new());
  if (!q) {
    return {Result::Fail, "BN_new faled: {}", LibreSSL::GetLastErrorString()};
  }

  BN_set_word(q.get(), 1);
  if (BN_cmp(publicKey, q.get()) <= 0) {
    return {Result::Fail, "The public key is too small."};
  }

  BN_copy(q.get(), p);
  if (BN_cmp(publicKey, q.get()) >= 0) {
    return {Result::Fail, "The public key is too large."};
  }

  return (Result::Success);
}

Result DiffieHellmanLibreSSLBN::DeriveSharedSecret(
    std::string_view hexPeerPublicKey, std::string* hexSharedSecret) const {
  ERR_clear_error();

  if (BN_num_bits(prime_.get()) > OPENSSL_DH_MAX_MODULUS_BITS) {
    return {Result::Fail, "Modulus too large."};
  }

  std::unique_ptr<BIGNUM, Base::DeleterFromFn<BN_free>> peerPublicKey(LibreSSL::ConvertHexToBigNum(hexPeerPublicKey));
  if (!peerPublicKey) {
    return {Result::Fail, "Could not convert the hex data to the public key: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (Result result = CheckPublicKey(prime_.get(), peerPublicKey.get()); !result) {
    return result;
  }

  std::unique_ptr<BN_CTX, Base::DeleterFromFn<BN_CTX_free>> ctx{BN_CTX_new()};
  if (!ctx) {
    return {Result::Fail, "Could not create the big number context: {}",
      LibreSSL::GetLastErrorString()};
  }

  BN_CTX_start(ctx.get());

  BIGNUM* tmp{BN_CTX_get(ctx.get())};
  if (!tmp) {
    return {Result::Fail, "Could not create the temporary big number: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (!BN_mod_exp(tmp, peerPublicKey.get(), privateKey_.get(), prime_.get(), ctx.get())) {
    return {Result::Fail, "Could not derive the shared secret: {}",
      LibreSSL::GetLastErrorString()};
  }

  int sharedSecretSize = BN_num_bytes(prime_.get());
  if (sharedSecretSize <= 0) {
    return {Result::Fail, "Could not get shared secret size"};
  }
  
  std::string sharedSecret;
  sharedSecret.resize(sharedSecretSize);

  if (!BN_bn2bin(tmp, static_cast<unsigned char*>(static_cast<void*>(&sharedSecret.front())))) {
    return {Result::Fail, "Could not extract the shared secret: {}",
      LibreSSL::GetLastErrorString()};
  }

  BN_CTX_end(ctx.get());

  *hexSharedSecret = Base::ConvertDataToHex(sharedSecret);

  return {Result::Success};
}

std::tuple<int, int> DiffieHellmanLibreSSLBN::GetPrimeLength() const {
  if (!prime_) {
    return {-1, -1};
  }
  return {BN_num_bits(prime_.get()), BN_num_bytes(prime_.get())};
}

std::tuple<int, int> DiffieHellmanLibreSSLBN::GetPrivateKeyLength() const {
  if (!privateKey_) {
    return {-1, -1};
  }
  return {BN_num_bits(privateKey_.get()), BN_num_bytes(privateKey_.get())};
}

std::tuple<int, int> DiffieHellmanLibreSSLBN::GetPublicKeyLength() const {
  if (!publicKey_) {
    return {-1, -1};
  }
  return {BN_num_bits(publicKey_.get()), BN_num_bytes(publicKey_.get())};
}
