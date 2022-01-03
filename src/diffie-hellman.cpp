// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diffie-hellman-libressl-dh.h"
#include "diffie-hellman-libressl-bn.h"
#include "diffie-hellman-boost.h"
#include "diffie-hellman.h"

std::unique_ptr<DiffieHellman> DiffieHellman::Create(Implementation impl) {
  switch (impl) {
    case Implementation::LibreSSLDH: return std::make_unique<DiffieHellmanLibreSSLDH>();
    case Implementation::LibreSSLBN: return std::make_unique<DiffieHellmanLibreSSLBN>();
    case Implementation::Boost: return std::make_unique<DiffieHellmanBoost>();
    default: break;
  }
  return std::unique_ptr<DiffieHellman>();
}


