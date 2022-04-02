// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <map>

#include "result.h"

// The Elliptic-curve Diffie-Hellman interface.
class ECDiffieHellman {
 public:

  enum class Implementation {
    Undefined = 0,
    OpenSSL,      // Based on OpenSSL 3
    LibreSSL,     // Based on LibreSSL 3
  };

  struct CurveInfo final {
    int internalId_ = 0;
    std::string name_;
    std::string comment_;
  };

  // Create an instance.
  static std::unique_ptr<ECDiffieHellman> Create(Implementation impl);

  // Default constructor.
  ECDiffieHellman() = default;

  // For derived classes.
  virtual ~ECDiffieHellman() {}

  // Gets implementation name.
  virtual std::string_view GetImplementationName() const = 0;

  // Gets supported curves.
  // Performance is not important for this project,
  // so std::map is used to show a sorted list instead of std::unordered_map.
  virtual Result GetSupportedCurves(std::map<std::string,
    CurveInfo>* curves) const = 0;

  // Sets the curve name.
  virtual Result SetCurveName(std::string_view curveName) = 0;

  // Gets the curve name.
  virtual Result GetCurveName(std::string* curveName) const = 0;

  // Generate a private key and then derives a public key.
  virtual Result GenerateKeys() = 0;

  // Gets the private key (for debug)
  virtual Result GetPrivateKey(std::string* hexPrivateKey) const = 0;

  // Gets the public key.
  virtual Result GetPublicKey(std::string* hexPublicKey) const = 0;

  // Derives the shared secret based on this objects values and the peer public key.
  virtual Result DeriveSharedSecret(std::string_view hexPeerPublicKey,
    std::string* hexSharedSecret) const = 0;

private:
  // Non-copyable.
  ECDiffieHellman(const ECDiffieHellman&) = delete;
  ECDiffieHellman& operator=(const ECDiffieHellman&) = delete;
};
