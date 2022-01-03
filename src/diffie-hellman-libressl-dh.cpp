// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <format>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "base-helpers.h"
#include "libressl-helpers.h"
#include "diffie-hellman-libressl-dh.h"

DiffieHellmanLibreSSLDH::DiffieHellmanLibreSSLDH()
: dh_(DH_new()) {
}

DiffieHellmanLibreSSLDH::~DiffieHellmanLibreSSLDH() {
}

std::string_view DiffieHellmanLibreSSLDH::GetImplementaionName() const {
  return "libressl DH";
}

Result DiffieHellmanLibreSSLDH::GenerateParameters(int primeLengthInBits, int generator) {
  ERR_clear_error();

  if (!DH_generate_parameters_ex(dh_.get(), primeLengthInBits, generator, nullptr)) {
    return {Result::Fail, "Could not generate DH parameters: {}",
      LibreSSL::GetLastErrorString()};
  }

  int codes = 0;
  if (!DH_check(dh_.get(), &codes)) {
    return {Result::Fail, "Could not check DH parameters: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (codes != 0) {
    return {Result::Fail, "Wrong DH parameters; codes: {}", codes};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLDH::SetParameters(std::string_view hexPrime, std::string_view hexGenerator) {
  ERR_clear_error();

  std::unique_ptr<BIGNUM, LibreSSL::BNDeleter> prime(LibreSSL::ConvertHexToBigNum(hexPrime));
  if (!prime) {
    return {Result::Fail, "Could not convert the hex data to the prime: {}",
      LibreSSL::GetLastErrorString()};
  }

  std::unique_ptr<BIGNUM, LibreSSL::BNDeleter> generator(LibreSSL::ConvertHexToBigNum(hexGenerator));
  if (!generator) {
    return {Result::Fail, "Could not convert the hex data to the generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (!DH_set0_pqg(dh_.get(), prime.get(), nullptr, generator.get())) {
    return {Result::Fail, "Could not set the prime and generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  (void)prime.release();
  (void)generator.release();

  return {Result::Success};
}

Result DiffieHellmanLibreSSLDH::GetParameters(std::string* hexPrime, std::string* hexGenerator) const {
  ERR_clear_error();

  const BIGNUM* prime = nullptr;
  const BIGNUM* generator = nullptr;
  
  DH_get0_pqg(dh_.get(), &prime, nullptr, &generator);
  if (!prime) {
    return {Result::Fail, "The prime is nullptr"};
  }
  if (!generator) {
    return {Result::Fail, "The generator is nullptr"};
  }

  hexPrime->clear();
  hexPrime->append(LibreSSL::ConvertBigNumToHex(prime));
  if (hexPrime->empty()) {
    return {Result::Fail, "Could not get prime: {}",
      LibreSSL::GetLastErrorString()};
  }
  
  hexGenerator->clear();
  hexGenerator->append(LibreSSL::ConvertBigNumToHex(generator));
  if (hexGenerator->empty()) {
    return {Result::Fail, "Could not get generator: {}",
      LibreSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLDH::GenerateKeys() {
  ERR_clear_error();

  if (!DH_generate_key(dh_.get())) {
    return {Result::Fail, "Could not generate the DH key pair: {}",
      LibreSSL::GetLastErrorString()};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLDH::GetPrivateKey(std::string* hexPrivateKey) const {
  ERR_clear_error();

  hexPrivateKey->clear();
  hexPrivateKey->append(LibreSSL::ConvertBigNumToHex(dh_->priv_key));
  if (hexPrivateKey->empty()) {
    return {Result::Fail, "The private key is empty."};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLDH::GetPublicKey(std::string* hexPublicKey) const {
  ERR_clear_error();

  const BIGNUM* publicKey = nullptr;
  DH_get0_key(dh_.get(), &publicKey, nullptr);  
  if (!publicKey) {
    return {Result::Fail, "The public key is null"};
  }

  hexPublicKey->clear();
  hexPublicKey->append(LibreSSL::ConvertBigNumToHex(publicKey));
  if (hexPublicKey->empty()) {
    return {Result::Fail, "The public key is empty."};
  }

  return {Result::Success};
}

Result DiffieHellmanLibreSSLDH::DeriveSharedSecret(
    std::string_view hexPeerPublicKey, std::string* hexSharedSecret) const {
  ERR_clear_error();

  std::unique_ptr<BIGNUM, LibreSSL::BNDeleter> peerPublicKey(
    LibreSSL::ConvertHexToBigNum(hexPeerPublicKey));
  if (!peerPublicKey) {
    return {Result::Fail, "Could not convert the hex data to the public key: {}",
      LibreSSL::GetLastErrorString()};
  }

  int sharedSecretSize = DH_size(dh_.get());
  if (sharedSecretSize <= 0) {
    return {Result::Fail, "It looks like the DH object is not configured."};
  }

  std::string sharedSecret;
  sharedSecret.resize(sharedSecretSize);

  sharedSecretSize = DH_compute_key(
    static_cast<unsigned char*>(static_cast<void*>(&sharedSecret.front())),
    peerPublicKey.get(), dh_.get());
  if (sharedSecretSize <= 0) {
    return {Result::Fail, "Could not derive the shared secret: {}",
      LibreSSL::GetLastErrorString()};
  }

  if (sharedSecretSize < sharedSecret.size()) {
    sharedSecret.resize(sharedSecretSize);
  }

  *hexSharedSecret = Base::ConvertDataToHex(sharedSecret);

  return {Result::Success};
}

std::tuple<int, int> DiffieHellmanLibreSSLDH::GetPrimeLength() const {
  return {DH_bits(dh_.get()), DH_size(dh_.get())};
}

std::tuple<int, int> DiffieHellmanLibreSSLDH::GetPrivateKeyLength() const {
  if (!dh_->priv_key) {
    return {-1, -1};
  }

  return {BN_num_bits(dh_->priv_key), BN_num_bytes(dh_->priv_key)};
}

std::tuple<int, int> DiffieHellmanLibreSSLDH::GetPublicKeyLength() const {
  const BIGNUM* publicKey = nullptr;
  DH_get0_key(dh_.get(), &publicKey, nullptr);
  if (!publicKey) {
    return {-1, -1};
  }

  return {BN_num_bits(publicKey), BN_num_bytes(publicKey)};
}

