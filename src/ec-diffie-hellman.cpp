// Copyright 2022 Eugen Hartmann. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#if defined(USE_OPENSSL)
#include "ec-diffie-hellman-openssl.h"
#else
#include "ec-diffie-hellman-libressl.h"
#endif

#include "ec-diffie-hellman.h"

std::unique_ptr<ECDiffieHellman> ECDiffieHellman::Create(Implementation impl) {
  switch (impl) {
#if defined(USE_OPENSSL)
    case Implementation::OpenSSL: return std::make_unique<ECDiffieHellmanOpenSSL>();
#else
    case Implementation::LibreSSL: return std::make_unique<ECDiffieHellmanLibreSSL>();
#endif
    default: break;
  }
  return std::unique_ptr<ECDiffieHellman>();
}
