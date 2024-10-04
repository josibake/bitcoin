// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <silentpaymentkey.h>
#include <span.h>

void SpPubKey::Encode(unsigned char code[BIP352_SPKEY_SIZE_IN_BYTES]) const
{
  // Should probably check that keys are compressed here
  memcpy(code, version, 1);
  memcpy(code+1, vchFingerprint, 4);
  memcpy(code+5, &fAllowLabels, 1);
  memcpy(code+6, scanKey.begin(), 32);
  memcpy(code+38, spendKey.begin(), 33);
}

void SpPubKey::Decode(const unsigned char code[BIP352_SPKEY_SIZE_IN_BYTES])
{
  memcpy(version, code, 1);
  memcpy(vchFingerprint, code+1, 4);
  memcpy(&fAllowLabels, code+5, 1);
  scanKey.Set(code+6, code+38, true);
  spendKey.Set(code+38, code+BIP352_SPKEY_SIZE_IN_BYTES);
}

CKeyID SpPubKey::GetID() const
{
  unsigned char code[BIP352_SPKEY_SIZE_IN_BYTES];
  Encode(code);
  return CKeyID(Hash160(Span(code, BIP352_SPKEY_SIZE_IN_BYTES)));
}

void SpKey::Encode(unsigned char code[BIP352_SPKEY_SIZE_IN_BYTES]) const
{
  // Should probably check that keys are compressed here
  memcpy(code, version, 1);
  memcpy(code+1, vchFingerprint, 4);
  memcpy(code+5, &fAllowLabels, 1);
  memcpy(code+6, scanKey.begin(), 32);
  code[38] = 0x00;
  memcpy(code+39, spendKey.begin(), 32);
}

void SpKey::Decode(const unsigned char code[BIP352_SPKEY_SIZE_IN_BYTES])
{
  if (code[38] != 0x00) {
    // return early leave SpKey invalid
    return;
  }
  memcpy(version, code, 1);
  memcpy(vchFingerprint, code+1, 4);
  memcpy(&fAllowLabels, code+5, 1);
  scanKey.Set(code+6, code+38, true);
  spendKey.Set(code+39, code+BIP352_SPKEY_SIZE_IN_BYTES, true);
}

SpPubKey SpKey::Neuter()
{
  SpPubKey ret;
  memcpy(ret.version, version, 1);
  memcpy(ret.vchFingerprint, vchFingerprint, 4);
  ret.fAllowLabels = fAllowLabels;
  ret.scanKey = scanKey;
  ret.spendKey = spendKey.GetPubKey();
  return ret;
}
