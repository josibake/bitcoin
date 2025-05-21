#!/usr/bin/env python3

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_raises_rpc_error,
)


class SilentPaymentsReceivingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_encrypt_and_decrypt(self):
        self.log.info("Check that a silent payments wallet can be encrypted and decrypted")
        self.log.info("Create encrypted wallet")
        self.nodes[0].createwallet(wallet_name="sp_encrypted", passphrase="unsigned integer", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("sp_encrypted")
        addr = wallet.getnewaddress(address_type="silent-payments")
        self.def_wallet.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        self.log.info("Check that we can scan without the wallet being unlocked")
        assert_equal(wallet.getbalance(), 10)
        self.log.info("Check that we get an error if trying to send with the wallet locked")
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wallet.sendtoaddress, addr, 9)
        wallet.walletpassphrase(passphrase="unsigned integer", timeout=3)
        self.log.info("Unlock wallet and send")
        wallet.sendtoaddress(addr, 9)
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 10, 0.0001)

    def test_encrypting_unencrypted(self):
        self.log.info("Check that a silent payments wallet can be encrypted after creation")
        self.log.info("Create un-encrypted wallet")
        self.nodes[0].createwallet(wallet_name="sp_unencrypted", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("sp_unencrypted")
        addr = wallet.getnewaddress(address_type="silent-payments")
        self.def_wallet.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        assert_equal(wallet.getbalance(), 10)
        self.log.info("Add a passphrase to the wallet")
        wallet.encryptwallet(passphrase="unsigned integer")
        self.log.info("Check that we get an error if trying to send with the wallet locked")
        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wallet.sendtoaddress, addr, 9)
        wallet.walletpassphrase(passphrase="unsigned integer", timeout=3)
        self.log.info("Unlock wallet and send")
        wallet.sendtoaddress(addr, 9)
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 10, 0.0001)

    def test_createwallet(self):
        self.log.info("Check createwallet silent payments option")

        self.nodes[0].createwallet(wallet_name="sp", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("sp")
        addr = wallet.getnewaddress(address_type="silent-payments")
        assert addr.startswith("sp")

        self.nodes[0].createwallet(wallet_name="non_sp", silent_payments=False)
        wallet = self.nodes[0].get_wallet_rpc("non_sp")
        assert_raises_rpc_error(-12, "Error: No silent-payments addresses available", wallet.getnewaddress, address_type="silent-payments")

    def test_basic(self):
        self.log.info("Basic receive and send")

        self.nodes[0].createwallet(wallet_name="basic", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("basic")

        addr = wallet.getnewaddress(address_type="silent-payments")
        addr_again = wallet.getnewaddress(address_type="silent-payments")
        assert addr == addr_again
        txid = self.def_wallet.sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)

        assert_equal(wallet.getbalance(), 10)
        wallet.gettransaction(txid)

        self.log.info("Test change address")
        change_addr = wallet.getrawchangeaddress(address_type="silent-payments")
        assert addr.startswith("sp")
        txid = self.def_wallet.sendtoaddress(change_addr, 5)
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 15)
        wallet.gettransaction(txid)

        self.log.info("Test self-transfer")
        txid = wallet.send({addr: 5})['txid']
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 15, 0.0001)
        assert(wallet.gettransaction(txid))
        self.log.info("Check that self-transfer is detected by listtransactions")
        assert(any(tx["txid"] == txid for tx in wallet.listtransactions()))

        self.log.info("Test self-transfer")
        txid = wallet.send({change_addr: 5})['txid']
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 15, 0.0001)
        assert(wallet.gettransaction(txid))
        self.log.info("Check that self-transfer to change address is not detected by listtransactions")
        assert(any(tx["txid"] == txid for tx in wallet.listtransactions()) == False)

        wallet.sendall([self.def_wallet.getnewaddress()])
        self.generate(self.nodes[0], 1)

        assert_equal(wallet.getbalance(), 0)

    def test_wallet_persistence(self):
        self.log.info("Test silent payments wallet persistence after closing and reopening")

        self.nodes[0].createwallet(wallet_name="persistence_test", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("persistence_test")
        addr = wallet.getnewaddress(address_type="silent-payments")
        send_amount = 15
        txid = self.def_wallet.sendtoaddress(addr, send_amount)
        self.generate(self.nodes[0], 1)

        # verify the wallet received the correct amount
        assert_equal(wallet.getbalance(), send_amount)
        tx = wallet.gettransaction(txid)
        self.nodes[0].unloadwallet("persistence_test")

        self.nodes[0].loadwallet("persistence_test")
        wallet = self.nodes[0].get_wallet_rpc("persistence_test")
        assert_equal(wallet.getbalance(), send_amount)
        loaded_tx = wallet.gettransaction(txid)
        assert_equal(tx, loaded_tx)

        self.disconnect_nodes(0, 1)
        txid = self.def_wallet.sendtoaddress(addr, send_amount)
        raw_tx = self.nodes[0].getrawtransaction(txid)
        def do_nothing():
            pass
        self.nodes[1].sendrawtransaction(raw_tx)
        self.generate(self.nodes[1], 1, sync_fun=do_nothing)
        self.nodes[0].unloadwallet("persistence_test")
        self.nodes[0].loadwallet("persistence_test")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        wallet = self.nodes[0].get_wallet_rpc("persistence_test")
        assert_equal(wallet.getbalance(), send_amount * 2)

        self.log.info("Wallet persistence verified successfully")

    def test_import_rescan(self):
        self.log.info("Check import rescan works for silent payments")

        self.nodes[0].createwallet(wallet_name="alice", silent_payments=True)
        self.nodes[0].createwallet(wallet_name="alice_wo", disable_private_keys=True, silent_payments=True)
        alice = self.nodes[0].get_wallet_rpc("alice")
        alice_wo = self.nodes[0].get_wallet_rpc("alice_wo")

        address = alice.getnewaddress(address_type="silent-payments")
        self.def_wallet.sendtoaddress(address, 10)
        blockhash = self.generate(self.nodes[0], 1)[0]
        timestamp = self.nodes[0].getblockheader(blockhash)["time"]
        assert_approx(alice.getbalance(), 10, 0.0001)
        assert_equal(alice_wo.getbalance(), 0)

        alice_sp_desc = [d["desc"] for d in alice.listdescriptors()["descriptors"] if d["desc"].startswith("sp(")][0]
        res = alice_wo.importdescriptors([{
            "desc": alice_sp_desc,
            "active": True,
            "next_index": 0,
            "timestamp": timestamp
        }])
        assert_equal(res[0]["success"], True)

        assert_approx(alice_wo.getbalance(), 10, 0.0001)

        self.log.info("Check descriptor update works for silent payments")
        # Import the same descriptor again to test the update
        res = alice_wo.importdescriptors([{
            "desc": alice_sp_desc,
            "active": True,
            "next_index": 0,
            "timestamp": timestamp
        }])
        assert_equal(res[0]["success"], True)

        assert_approx(alice_wo.getbalance(), 10, 0.0001)

    def test_rbf(self):
        self.log.info("Check Silent Payments RBF")

        self.nodes[0].createwallet(wallet_name="craig", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("craig")
        address = wallet.getnewaddress(address_type="silent-payments")

        txid = self.def_wallet.sendtoaddress(address, 49.99, replaceable=True)
        assert_equal(self.nodes[0].getrawmempool(), [txid])
        raw_tx = self.nodes[0].getrawtransaction(txid)
        tx = self.nodes[0].decoderawtransaction(raw_tx)
        assert_equal(len(tx["vin"]), 1)

        psbt = self.def_wallet.psbtbumpfee(txid, fee_rate=10000)["psbt"]
        decoded = self.nodes[0].decodepsbt(psbt)
        assert_equal(len(decoded["tx"]["vin"]), 2)

        res = self.def_wallet.walletprocesspsbt(psbt)
        assert_equal(res["complete"], True)
        txid = self.def_wallet.sendrawtransaction(res["hex"])
        assert_equal(self.nodes[0].getrawmempool(), [txid])

        assert_equal(wallet.getbalance(), 0)
        self.generate(self.nodes[0], 1)
        assert_approx(wallet.getbalance(), 49.99, 0.0001)

    def test_conflict(self):
        self.log.info("Check Silent Payments wallet handles conflicts")

        self.nodes[0].createwallet(wallet_name="conflict", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("conflict")
        address = wallet.getnewaddress(address_type="bech32m")
        unspents = self.def_wallet.listunspent()
        # walletcreatefundedpsbt fails when receipients include silent-payment addresses
        # use bech32m instead
        psbt = self.def_wallet.walletcreatefundedpsbt(inputs=[unspents[0]], outputs=[{address : 49.99}])["psbt"]
        tx1 = self.def_wallet.walletprocesspsbt(psbt=psbt, finalize=True)['hex']

        # Create tx2 to spend the same input as tx1
        psbt = self.def_wallet.walletcreatefundedpsbt(inputs=[unspents[0]], outputs=[{self.def_wallet.getnewaddress() : 49.99}])["psbt"]
        tx2 =  self.def_wallet.walletprocesspsbt(psbt=psbt, finalize=True)['hex']

        self.nodes[0].sendrawtransaction(tx1)

        # Mine conflicting transaction on node 1
        self.disconnect_nodes(0, 1)
        self.nodes[1].sendrawtransaction(tx2)
        self.generate(self.nodes[1], 1, sync_fun=self.no_op)

        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(wallet.getbalance(), 0)

    def test_createwallet_descriptor(self):
        self.log.info("Check createwalletdescriptor works with silent payments descriptor")

        self.nodes[0].createwallet(wallet_name="sp_desc", silent_payments=True,)
        wallet = self.nodes[0].get_wallet_rpc("sp_desc")
        xpub_info = wallet.gethdkeys(private=True)
        xprv = xpub_info[0]["xprv"]
        expected_descs = []
        for desc in wallet.listdescriptors(private=True)["descriptors"]:
            if desc["desc"].startswith("sp("):
                expected_descs.append(desc["desc"])

        self.nodes[0].createwallet("blank", blank=True)
        blank_wallet = self.nodes[0].get_wallet_rpc("blank")

        # Import one active descriptor
        assert_equal(blank_wallet.importdescriptors([{"desc": descsum_create(f"pkh({xprv}/44h/2h/0h/0/0/*)"), "timestamp": "now", "active": True}])[0]["success"], True)
        assert_equal(len(blank_wallet.listdescriptors()["descriptors"]), 1)
        assert_equal(len(blank_wallet.gethdkeys()), 1)

        blank_wallet.createwalletdescriptor(type="silent-payments", internal=False)
        new_descs = [d for d in blank_wallet.listdescriptors(private=True)["descriptors"] if d["desc"].startswith("sp(")]
        assert_equal([d['desc'] for d in new_descs], expected_descs)
        for desc in new_descs:
            assert_equal(desc["active"], True)
            # Silent Payments descriptors are both internal and external
            # The wallet only checks if a descriptor is internal
            # because it does not expect a descriptor to be both internal and external
            # Hence, this flag will be 'True'
            assert_equal(desc["internal"], True)

    def test_getaddressinfo(self):
        self.log.info("Check getaddressinfo works with silent payments addresses")

        self.nodes[0].createwallet(wallet_name="sp_info", silent_payments=True)
        wallet = self.nodes[0].get_wallet_rpc("sp_info")
        def test_addressinfo(addr):
            info = wallet.getaddressinfo(addr)
            desc = info["parent_desc"]
            assert_equal(info["ismine"], True)
            assert_equal(info["solvable"], False)
            assert_equal(info["iswatchonly"], False)

            txid = self.def_wallet.sendtoaddress(addr, 10)
            self.generate(self.nodes[0], 1)
            tx = wallet.gettransaction(txid)
            onchain_addr = tx['details'][0]['address']
            info = wallet.getaddressinfo(onchain_addr)
            assert_equal(info["ismine"], True)
            assert_equal(info["solvable"], True)
            assert_equal(info["iswatchonly"], False)
            assert_equal(info["parent_desc"], desc)

        test_addressinfo(wallet.getnewaddress(address_type="silent-payments"))
        test_addressinfo(wallet.getrawchangeaddress(address_type="silent-payments"))

    def run_test(self):
        self.def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.generate(self.nodes[0], 102)

        self.test_rbf()
        self.test_createwallet()
        self.test_encrypt_and_decrypt()
        self.test_encrypting_unencrypted()
        self.test_basic()
        self.test_wallet_persistence()
        self.test_import_rescan()
        self.test_createwallet_descriptor()
        self.test_getaddressinfo()
        self.test_conflict()



if __name__ == '__main__':
    SilentPaymentsReceivingTest(__file__).main()
