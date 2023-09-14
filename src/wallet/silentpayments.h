#ifndef BITCOIN_WALLET_SILENTPAYMENTS_H
#define BITCOIN_WALLET_SILENTPAYMENTS_H

#include <addresstype.h>
#include <coins.h>
#include <key_io.h>
#include <undo.h>

namespace wallet {
CPubKey ComputeECDH(const CKey& seckey, const CPubKey& pubkey, const uint256& inputs_hash);
uint256 ComputeInputsHash(const std::vector<COutPoint>& tx_outpoints, const CPubKey& sum_input_pubkeys);
uint256 ComputeSharedSecretTweak(const CPubKey& ecdh_pubkey, const uint32_t k);
uint256 ComputeSilentPaymentLabelTweak(const CKey& scan_key, const int m);
V0SilentPaymentDestination GenerateSilentPaymentLabeledAddress(const V0SilentPaymentDestination& receiver, const uint256& label);
std::map<size_t, WitnessV1Taproot> GenerateSilentPaymentTaprootDestinations(const CKey& seckey, const uint256& inputs_hash, const std::map<size_t, V0SilentPaymentDestination>& sp_dests);
std::optional<std::pair<uint256, CPubKey>> GetSilentPaymentTweakDataFromTxInputs(const std::vector<CTxIn>& vin, const std::map<COutPoint, Coin>& coins);
std::optional<CPubKey> GetPubKeyFromInput(const CTxIn& txin, const CScript& spk);
std::vector<uint256> GetTxOutputTweaks(const CPubKey& spend_pubkey, const CPubKey& ecdh_pubkey, std::vector<XOnlyPubKey> output_pub_keys, const std::map<CPubKey, uint256>& labels);
CKey SumInputPrivKeys(const std::vector<std::pair<CKey, bool>>& sender_secret_keys); // For the unit tests
CPubKey SumInputPubKeys(const std::vector<CPubKey>& input_pubkeys); // For the unit tests
} // namespace wallet
#endif // BITCOIN_WALLET_SILENTPAYMENTS_H
