#include <wallet/silentpayments.h>
#include <addresstype.h>
#include <arith_uint256.h>
#include <coins.h>
#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <key_io.h>
#include <undo.h>
#include <logging.h>
#include <pubkey.h>
#include <policy/policy.h>
#include <script/sign.h>
#include <script/solver.h>
#include <util/check.h>

namespace wallet {

SilentPaymentsSPKM::SilentPaymentsSPKM(WalletStorage& storage, const uint256& id, const V0SilentPaymentDestination& address, const CKey& scan_key, const CKey& spend_key, const std::vector<unsigned char>& spend_ckey, const std::vector<uint256>& tweaks, int64_t labels_size, int64_t creation_time, int64_t labels_used)
    : ScriptPubKeyMan(storage),
    m_address(address),
    m_scan_key(scan_key),
    m_spend_key(spend_key),
    m_spend_crypted_key(spend_ckey),
    m_creation_time(creation_time),
    m_labels_used(labels_used),
    m_id(id)
{
    LOCK(cs_sp_man);
    // Create the scriptPubKeys given the tweaks and store them in memory
    for (const uint256& tweak : tweaks) {
        CPubKey output_key{m_address.m_spend_pubkey};
        output_key.TweakAdd(tweak.data());
        m_spk_tweaks.emplace(GetScriptForDestination(WitnessV1Taproot(XOnlyPubKey{output_key})), tweak);
    }

    // Setup labels and change
    SetupLabels(labels_size);
}

SilentPaymentsSPKM::SilentPaymentsSPKM(WalletStorage& storage, int64_t labels_size, const CExtKey& master_key)
    : ScriptPubKeyMan(storage),
    m_creation_time(GetTime()),
    m_labels_used(0)
{
    LOCK(cs_sp_man);
    if (m_storage.HasEncryptionKeys() && m_storage.IsLocked()) {
        throw std::runtime_error("Wallet locked; Unable to write spend key");
    }

    // Derive the spend key at m/352h/0h/0h/0h/0
    CExtKey derived = master_key;
    for (uint32_t i : std::vector<uint32_t>{352 | 0x80000000, (Params().IsTestChain() ? 1 : 0) | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0}) {
        if (!derived.Derive(derived, i)) {
            throw std::runtime_error("Unable to derive silent payments spend key");
        }
    }
    m_address.m_spend_pubkey = derived.key.GetPubKey();
    if (m_storage.HasEncryptionKeys()) {
        std::vector<unsigned char> crypted_spend_key;
        CKeyingMaterial secret{UCharCast(derived.key.begin()), UCharCast(derived.key.end())};
        if (!m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) { return EncryptSecret(encryption_key, secret, derived.key.GetPubKey().GetHash(), crypted_spend_key);})) {
            throw std::runtime_error("Unable to encrypt silent payments spend key");
        }
        m_spend_crypted_key = crypted_spend_key;
    } else {
        m_spend_key = derived.key;
    }

    // Derive the scan key
    derived = master_key;
    for (uint32_t i : std::vector<uint32_t>{352 | 0x80000000, (Params().IsTestChain() ? 1 : 0) | 0x80000000, 0 | 0x80000000, 1 | 0x80000000, 0}) {
        if (!derived.Derive(derived, i)) {
            throw std::runtime_error("Unable to derive silent payments scan key");
        }
    }
    m_address.m_scan_pubkey = derived.key.GetPubKey();
    m_scan_key = derived.key;

    // Calculate the spkm id by hashing the pubkeys together
    // The method for calculating the id just needs to be mostly random, we do not rely on being able to calculate it again in the future
    // and instead just use the stored value
    HashWriter hasher;
    hasher << m_address.m_scan_pubkey;
    hasher << m_address.m_spend_pubkey;
    m_id = hasher.GetSHA256();

    // Store the spend key
    WalletBatch batch(m_storage.GetDatabase());
    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            throw std::runtime_error("Wallet locked; Unable to write spend key");
        }
        if (!batch.WriteSilentPaymentsSpendCryptedKey(GetID(), m_spend_crypted_key, m_address.m_spend_pubkey)) {
            throw std::runtime_error("Unable to write spend key to database");
        }
    } else {
        if (!batch.WriteSilentPaymentsSpendKey(GetID(), m_spend_key.GetPrivKey(), m_address.m_spend_pubkey)) {
            throw std::runtime_error("Unable to write spend key to database");
        }
    }
    // Store the scan key
    // This key cannot be encrypted
    if (!batch.WriteSilentPaymentsScanKey(GetID(), m_scan_key.GetPrivKey(), m_address.m_scan_pubkey)) {
        throw std::runtime_error("Unable to write scan key to database");
    }

    // Store creation time and max label used
    batch.WriteSilentPaymentsMetadata(GetID(), m_creation_time, m_labels_used);

    // Setup labels and change
    SetupLabels(labels_size);
}

void SilentPaymentsSPKM::SetupLabels(int64_t labels_size)
{
    AssertLockHeld(cs_sp_man);
    // Create the label curve points map
    for (arith_uint256 i = 1; i < labels_size; ++i) {
        uint256 label_data = ArithToUint256(i);
        CKey label;
        label.Set(label_data.begin(), label_data.end(), /*fCompressedIn=*/true);
        m_sp_labels.emplace(label.GetPubKey(), label_data);
    }

    // Derive the change label and set the change destination
    const uint256 change_tweak = BIP352::CreateLabelTweak(m_scan_key, 0).second;
    m_change_address = BIP352::GenerateSilentPaymentLabelledAddress(m_address, change_tweak);
    CKey change_key;
    change_key.Set(change_tweak.begin(), change_tweak.end(), /*fCompressedIn=*/true);
    m_sp_labels.emplace(change_key.GetPubKey(), change_tweak);
}

util::Result<CTxDestination> SilentPaymentsSPKM::GetNewDestination(const OutputType type)
{
    LOCK(cs_sp_man);
    if (type != OutputType::SILENT_PAYMENT) {
        throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
    }

    return CTxDestination{m_address};
}

isminetype SilentPaymentsSPKM::IsMine(const CScript& script) const
{
    LOCK(cs_sp_man);
    return m_spk_tweaks.count(script) > 0 ? ISMINE_SPENDABLE : ISMINE_NO;
}

bool SilentPaymentsSPKM::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_sp_man);
    assert(!m_spend_key.IsValid());

    CKey key;
    std::vector<unsigned char> crypted_secret = m_spend_crypted_key;
    CPubKey spend_pubkey = m_address.m_spend_pubkey;
    if (!DecryptKey(master_key, crypted_secret, spend_pubkey, key)) {
        throw std::runtime_error("Error unlocking wallet: unable to decrypt silent payments spend key. Your wallet file may be corrupt.");
    }
    return true;
}

bool SilentPaymentsSPKM::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_sp_man);
    assert(m_spend_key.IsValid());
    assert(m_spend_crypted_key.empty());

    CPubKey pubkey = m_spend_key.GetPubKey();
    CKeyingMaterial secret{UCharCast(m_spend_key.begin()), UCharCast(m_spend_key.end())};
    std::vector<unsigned char> crypted_secret;
    if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
        return false;
    }
    m_spend_crypted_key = crypted_secret;
    batch->WriteSilentPaymentsSpendCryptedKey(GetID(), crypted_secret, pubkey);
    m_spend_key.Invalidate();
    return true;
}

util::Result<CTxDestination> SilentPaymentsSPKM::GetReservedDestination(const OutputType type, bool internal, int64_t& index, CKeyPool& keypool)
{
    LOCK(cs_sp_man);
    if (type != OutputType::SILENT_PAYMENT) {
        throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
    }

    // Set index to 0 so callers don't get confused
    index = 0;
    return CTxDestination{m_change_address};
}

bool SilentPaymentsSPKM::TopUp(unsigned int size)
{
    LOCK(cs_sp_man);
    std::set<CScript> new_spks;
    for (const auto& spk : m_spk_tweaks) {
        new_spks.emplace(spk.first);
    }
    m_storage.TopUpCallback(new_spks, this);
    return true;
}

std::optional<int64_t> SilentPaymentsSPKM::GetOldestKeyPoolTime() const
{
    // This is only used for getwalletinfo output and isn't relevant to silent payments wallets.
    return std::nullopt;
}

unsigned int SilentPaymentsSPKM::GetKeyPoolSize() const
{
    // Keypool size doesn't make sense for silent payments, just return 0
    return 0;
}

int64_t SilentPaymentsSPKM::GetTimeFirstKey() const
{
    LOCK(cs_sp_man);
    return m_creation_time;
}

std::unique_ptr<CKeyMetadata> SilentPaymentsSPKM::GetMetadata(const CTxDestination& dest) const
{
    // The concept of metadata for individual silent payments addresses doesn't really work, so return nothing for now
    return nullptr;
}

std::unique_ptr<FlatSigningProvider> SilentPaymentsSPKM::GetSigningProvider(const CScript& script, bool include_private) const
{
    AssertLockHeld(cs_sp_man);
    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();

    // We can only provide solving data for the scripts we have already discovered
    if (m_spk_tweaks.count(script) == 0) {
        return out_keys;
    }

    const uint256& tweak = m_spk_tweaks.at(script);
    CPubKey output_pubkey{m_address.m_spend_pubkey};
    output_pubkey.TweakAdd(tweak.data());

    out_keys->pubkeys.emplace(output_pubkey.GetID(), output_pubkey);

    if (include_private) {
        CKey output_key;
        std::vector<unsigned char> crypted_spend_key = m_spend_crypted_key;
        CPubKey spend_pubkey = m_address.m_spend_pubkey;
        if (m_storage.HasEncryptionKeys()) {
            if (!m_storage.IsLocked()) {
                if (m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) { return DecryptKey(encryption_key, crypted_spend_key, spend_pubkey, output_key); })) {
                    output_key.TweakAdd(tweak.data());
                } else {
                    assert(false);
                }
            }
        } else {
            output_key = m_spend_key;
            output_key.TweakAdd(tweak.data());
        }
        if (output_key.IsValid()) {
            assert(output_key.GetPubKey() == output_pubkey);
            out_keys->keys.emplace(output_key.GetPubKey().GetID(), output_key);
        }
    }

    return out_keys;
}

std::unique_ptr<SigningProvider> SilentPaymentsSPKM::GetSolvingProvider(const CScript& script) const
{
    LOCK(cs_sp_man);
    return GetSigningProvider(script, false);
}

bool SilentPaymentsSPKM::CanProvide(const CScript& script, SignatureData& sigdata)
{
    LOCK(cs_sp_man);
    return m_spk_tweaks.count(script) > 0;
}

bool SilentPaymentsSPKM::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    LOCK(cs_sp_man);
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair: coins) {
        std::unique_ptr<FlatSigningProvider> coin_keys = GetSigningProvider(coin_pair.second.out.scriptPubKey, /*include_private=*/true);
        if (!coin_keys) continue;
        keys->Merge(std::move(*coin_keys));
    }

    return ::SignTransaction(tx, keys.get(), coins, sighash, input_errors);
}

SigningResult SilentPaymentsSPKM::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    // Message signing is not available for taproot outputs, so doesn't apply here
    return SigningResult::SIGNING_FAILED;
}
TransactionError SilentPaymentsSPKM::FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, int sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize) const
{
    LOCK(cs_sp_man);
    if (n_signed) {
        *n_signed = 0;
    }
    for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
        const CTxIn& txin = psbt.tx->vin[i];
        PSBTInput& input = psbt.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the Sighash type
        if (sign && input.sighash_type != std::nullopt && *input.sighash_type != sighash_type) {
            return TransactionError::SIGHASH_MISMATCH;
        }

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (txin.prevout.n >= input.non_witness_utxo->vout.size()) {
                return TransactionError::MISSING_INPUTS;
            }
            script = input.non_witness_utxo->vout[txin.prevout.n].scriptPubKey;
        } else {
            // There's no UTXO so we can just skip this now
            continue;
        }
        SignatureData sigdata;
        input.FillSignatureData(sigdata);

        std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(script, /*include_private=*/sign);
        SignPSBTInput(HidingSigningProvider(keys.get(), /*hide_secret=*/!sign, /*hide_origin=*/!bip32derivs), psbt, i, &txdata, sighash_type, nullptr, finalize);

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // No need to fill in output data since there is no bip32 derivation done or scripts.

    return TransactionError::OK;
}

uint256 SilentPaymentsSPKM::GetID() const
{
    return m_id;
}

std::unordered_set<CScript, SaltedSipHasher> SilentPaymentsSPKM::GetScriptPubKeys() const
{
    LOCK(cs_sp_man);
    std::unordered_set<CScript, SaltedSipHasher> spks;
    std::transform(m_spk_tweaks.cbegin(), m_spk_tweaks.cend(), std::inserter(spks, spks.end()), [](const auto& pair) { return pair.first; });
    return spks;
}

bool SilentPaymentsSPKM::AddTweakWithDB(WalletBatch& batch, const uint256& tweak)
{
    AssertLockHeld(cs_sp_man);
    CPubKey tweaked_pub{m_address.m_spend_pubkey};
    tweaked_pub.TweakAdd(tweak.data());
    const auto spk = GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{tweaked_pub}});
    m_spk_tweaks.emplace(spk, tweak);
    m_storage.TopUpCallback({spk}, this);
    return batch.WriteSilentPaymentsTweak(GetID(), tweak);
}

isminetype SilentPaymentsSPKM::IsMineSilentPayments(const CTransaction& tx, const std::map<COutPoint, Coin>& coins)
{
    // Coinbases cannot be silent payments
    if (tx.IsCoinBase()) {
        return ISMINE_NO;
    }

    // Extract the taproot output keys
    std::vector<XOnlyPubKey> output_keys;
    for (const CTxOut& txout : tx.vout) {
        std::vector<std::vector<unsigned char>> solutions;
        TxoutType type = Solver(txout.scriptPubKey, solutions);
        if (type == TxoutType::WITNESS_V1_TAPROOT) {
            output_keys.emplace_back(solutions[0]);
        } else if (type == TxoutType::WITNESS_UNKNOWN) {
            // Cannot have outputs with unknown witness versions
            return ISMINE_NO;
        }
    }
    // Must have at least one taproot output
    if (output_keys.size() == 0) return ISMINE_NO;
    // If we did not extract any pubkeys, not mine.
    auto public_data = BIP352::GetSilentPaymentsPublicData(tx.vin, coins);
    if (!public_data.has_value()) return ISMINE_NO;

    LOCK(cs_sp_man);
    // Retrieve the output tweaks
    auto tweaks = BIP352::ScanForSilentPaymentOutputs(m_scan_key, *public_data, m_address.m_spend_pubkey, output_keys, m_sp_labels);

    // If no tweaks, not mine
    if (!tweaks.has_value()) {
        return ISMINE_NO;
    }

    // This tx is mine, store the tweaks and return ISMINE_SPENDABLE
    WalletBatch batch(m_storage.GetDatabase());
    for (const auto& tweak : *tweaks) {
        if (!AddTweakWithDB(batch, tweak.tweak)) {
            throw std::runtime_error(std::string(__func__) + ": writing tweak failed");
        }
    }
    return ISMINE_SPENDABLE;
}

std::pair<CKey, bool> SilentPaymentsSPKM::GetPrivKeyForSilentPayment(const CScript& scriptPubKey) const
{
    LOCK(cs_sp_man);
    if (!IsMine(scriptPubKey)) return {};

    std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(scriptPubKey, /*include_private=*/true);
    return {keys->keys.begin()->second, true};
}
}
