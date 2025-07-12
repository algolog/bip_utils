"""Example of Algorand keys derivation using ARC-0052 / BIP32 xHD wallet (Peikert type)"""

from bip_utils import (
    AlgoAddrEncoder,
    Bip32KeyIndex,
    Bip39SeedGenerator,
)
from bip32_peikert_ed25519 import Bip32PeikertEd25519


mnemonic = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
print(f"BIP39 mnemonic: {mnemonic}")
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

account_hd_path = f"m/44'/283'/0'"
account_node = Bip32PeikertEd25519.FromSeedAndPath(seed_bytes, account_hd_path)
account_node.ConvertToPublic()  # remove private key for testing public derivation

for i in range(5):
    hd_path = f"{account_hd_path}/0/{i}"

    # private derivation with full path
    bip32_ctx = Bip32PeikertEd25519.FromSeedAndPath(seed_bytes, hd_path)
    private_key = bip32_ctx.PrivateKey()
    public_key = bip32_ctx.PublicKey().KeyObject()
    algorand_address = AlgoAddrEncoder().EncodeKey(public_key)

    # public derivation
    pub_ctx2 = account_node.ChildKey(0).ChildKey(i)
    public_key2 = pub_ctx2.PublicKey().KeyObject()
    algorand_address2 = AlgoAddrEncoder().EncodeKey(public_key2)

    assert algorand_address == algorand_address2

    print(f"{hd_path}: {algorand_address}")
