# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Module for keys derivation based on ed25519 curve as defined by BIP32 Khovratovich/Law with Peikert's amendments."""

# Imports
from typing import Type, Tuple
from bip_utils import Bip32KholawEd25519
from nacl.bindings import (
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_reduce,
    crypto_hash_sha512,
    crypto_scalarmult_ed25519_base_noclamp,
)

# Imports from bip32_peikert_ed25519_key_derivator
from bip_utils.bip.bip32.bip32_ex import Bip32KeyError
from bip_utils.bip.bip32.bip32_key_data import Bip32KeyIndex
from bip_utils.bip.bip32.bip32_keys import Bip32PublicKey
from bip_utils.bip.bip32.kholaw.bip32_kholaw_key_derivator_base import (
    Bip32KholawEd25519KeyDerivatorBase,
)
from bip_utils.ecc import Ed25519KholawPrivateKey, EllipticCurve, IPoint
from bip_utils.utils.misc import BytesUtils, BitUtils, IntegerUtils

# Imports from bip32_peikert_ed25519_mst_key_generator
from bip_utils.bip.bip32.base import IBip32MstKeyGenerator
from bip_utils.bip.bip32.slip10.bip32_slip10_mst_key_generator import (
    Bip32Slip10MstKeyGeneratorConst,
)
from bip_utils.utils.crypto import HmacSha512, Sha512, Sha256
from bip_utils.utils.misc import BitUtils
from bip_utils.ecc.ed25519.ed25519_keys import Ed25519PrivateKey


class Bip32PeikertEd25519(Bip32KholawEd25519):
    """
    BIP32-Ed25519 Khovratovich/Law/Peikert xHD keys class, Algorand ARC-0052 Peikert type.
    It allows master keys generation and keys derivation using ed25519 curve.

    The Khovratovich vs. Peikert difference lies in how many bits of randomization are
    performed when deriving a new child key.
    Khovratovic keeps 32 bits (4 bytes) and randomizes 256-32=224bits.
    Peikert on the other hand keeps 9 bits and randomizes 256-9 = 254 bits at each level.
    The Peikert derivation type is thus more secure, but only allows for 8 safe levels of derivation,
    whereas the Khovratovic allows for 2^26 (https://github.com/algorandfoundation/xHD-Wallet-API-kt).
    """

    DERIVATION_TYPE_G_BITS = 9  #  9 for Peikert's (Pera and Lute wallets compatible), 32 for Khovratovich/Law

    @staticmethod
    def _KeyDerivator():
        return Bip32PeikertEd25519KeyDerivator

    @staticmethod
    def _MasterKeyGenerator():
        return Bip32PeikertEd25519MstKeyGenerator

    @staticmethod
    def raw_sign(
        private_key: Ed25519KholawPrivateKey,
        data: bytes,
    ) -> bytes:
        """
        Raw Signing function for BIP32-ed25519 HD wallets
        Edwards-Curve Digital Signature Algorithm (EdDSA)
        Ref: https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.6

        Args:
            private_key (Ed25519KholawPrivateKey object): Ed25519KholawPrivateKey object
            data (bytes): Data to be signed in raw bytes

        Returns:
            bytes: Signature holding R + S, totally 64 bytes
        """
        raw_key = private_key.Raw()
        scalar = raw_key[:Ed25519PrivateKey.Length()]  # private_key.m_sign_key
        kR = raw_key[Ed25519PrivateKey.Length():]      # private_key.m_ext_key

        # \(1): pubKey = scalar * G (base point, no clamp)
        publicKey = crypto_scalarmult_ed25519_base_noclamp(scalar)

        # \(2): h = hash(c || msg) mod q
        r = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(kR + data))

        # \(4):  R = r * G (base point, no clamp)
        R = crypto_scalarmult_ed25519_base_noclamp(r)

        # h = hash(R || pubKey || msg) mod q
        h = crypto_core_ed25519_scalar_reduce(crypto_hash_sha512(R + publicKey + data))

        # \(5): S = (r + h * k) mod q
        S = crypto_core_ed25519_scalar_add(r, crypto_core_ed25519_scalar_mul(h, scalar))

        return R + S


class Bip32PeikertEd25519MstKeyGenerator(IBip32MstKeyGenerator):
    """
    BIP32 Khovratovich/Law/Peikert ed25519 master key generator class.
    It allows master keys generation in accordance with Algorand ARC-0052 / BIP32.
    """

    @classmethod
    def GenerateFromSeed(cls, seed_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Generate a master key from the specified seed.

        Args:
            seed_bytes (bytes): Seed bytes

        Returns:
            tuple[bytes, bytes]: Private key bytes (index 0) and chain code bytes (index 1)

        Raises:
            Bip32KeyError: If the seed is not suitable for master key generation
            ValueError: If seed length is not valid
        """
        if len(seed_bytes) < Bip32Slip10MstKeyGeneratorConst.SEED_MIN_BYTE_LEN:
            raise ValueError(f"Invalid seed length ({len(seed_bytes)})")

        # Compute kL and kR
        k = Sha512.QuickDigest(seed_bytes)
        kl_bytes = k[:Ed25519PrivateKey.Length()]
        kr_bytes = k[Ed25519PrivateKey.Length():]

        # hash repeatedly while the third highest bit of the last byte of kl is not zero
        while BitUtils.AreBitsSet(kl_bytes[31], 0x20):
            kl_bytes, kr_bytes = HmacSha512.QuickDigestHalves(kl_bytes, kr_bytes)

        # Tweak kL bytes
        kl_bytes = cls.__TweakMasterKeyBits(kl_bytes)

        # Compute chain code
        chain_code_bytes = Sha256.QuickDigest(b"\x01" + seed_bytes)

        return kl_bytes + kr_bytes, chain_code_bytes


    @staticmethod
    def __TweakMasterKeyBits(key_bytes: bytes) -> bytes:
        """
        Tweak master key bits.

        Args:
            key_bytes (bytes): Key bytes

        Returns:
            bytes: Tweaked key bytes
        """
        key_bytes = bytearray(key_bytes)
        # Clear the lowest 3 bits of the first byte of kL
        key_bytes[0] = BitUtils.ResetBits(key_bytes[0], 0x07)
        # Clear the highest bit of the last byte of kL
        key_bytes[31] = BitUtils.ResetBits(key_bytes[31], 0x80)
        # Set the second-highest bit of the last byte of kL
        key_bytes[31] = BitUtils.SetBits(key_bytes[31], 0x40)

        return bytes(key_bytes)


class Bip32PeikertEd25519KeyDerivator(Bip32KholawEd25519KeyDerivatorBase):
    """
    Algorand ARC-0052 Khovratovich/Law/Peikert ed25519 key derivator class.
    It allows keys derivation for ed25519 curves according to ARC-0052 / BIP32.
    """

    @staticmethod
    def trunc_256_minus_g_bits(
        zl: bytes,
        g: int = Bip32PeikertEd25519.DERIVATION_TYPE_G_BITS
    ) -> bytes:
        truncated = bytearray(zl)
        remaining_bits = g

        # Start from the last byte and move backwards
        for i in range(len(truncated))[::-1]:
            if remaining_bits >= 8:
                # If more than 8 bits remain to be zeroed, zero the entire byte
                truncated[i] = 0
                remaining_bits -= 8
            else:
                # Zero out the most significant bits
                truncated[i] &= (0xFF >> remaining_bits)
                break

        return bytes(truncated)


    @staticmethod
    def _SerializeIndex(index: Bip32KeyIndex) -> bytes:
        """
        Serialize key index.

        Args:
            index (Bip32KeyIndex object): Key index

        Returns:
            bytes: Serialized index
        """
        return index.ToBytes(endianness="little")

    @staticmethod
    def _NewPrivateKeyLeftPart(zl_bytes: bytes,
                               kl_bytes: bytes,
                               curve: EllipticCurve) -> bytes:
        """
        Compute the new private key left part for private derivation.

        Args:
            zl_bytes (bytes)            : Leftmost Z 32-byte
            kl_bytes (bytes)            : Leftmost private key 32-byte
            curve (EllipticCurve object): EllipticCurve object

        Returns:
            bytes: Leftmost new private key 32-byte
        """
        ## ######################################
        ## Standard BIP32-ed25519 derivation
        ## #######################################
        ## zL = 8 * 28bytesOf(z_left_hand_side)

        ## ######################################
        ## Chris Peikert's ammendment to BIP32-ed25519 derivation
        ## #######################################
        ## zL = 8 * trunc_256_minus_g_bits (z_left_hand_side, g)

        #zl_int = BytesUtils.ToInteger(zl_bytes[:28], endianness="little")
        zl_int = BytesUtils.ToInteger(
            Bip32PeikertEd25519KeyDerivator.trunc_256_minus_g_bits(zl_bytes),
            endianness="little",
        )
        kl_int = BytesUtils.ToInteger(kl_bytes, endianness="little")

        prvl_int = (zl_int * 8) + kl_int
        # Discard child if multiple of curve order
        if prvl_int % curve.Order() == 0:
            raise Bip32KeyError("Computed child key is not valid, very unlucky index")

        return IntegerUtils.ToBytes(prvl_int,
                                    bytes_num=Ed25519KholawPrivateKey.Length() // 2,
                                    endianness="little")

    @staticmethod
    def _NewPrivateKeyRightPart(zr_bytes: bytes,
                                kr_bytes: bytes) -> bytes:
        """
        Compute the new private key right part for private derivation.

        Args:
            zr_bytes (bytes): Rightmost Z 32-byte
            kr_bytes (bytes): Rightmost private key 32-byte

        Returns:
            bytes: Rightmost new private key 32-byte
        """
        zr_int = BytesUtils.ToInteger(zr_bytes, endianness="little")
        kpr_int = BytesUtils.ToInteger(kr_bytes, endianness="little")
        kr_int = (zr_int + kpr_int) % (2 ** 256)

        return IntegerUtils.ToBytes(kr_int,
                                    bytes_num=Ed25519KholawPrivateKey.Length() // 2,
                                    endianness="little")

    @staticmethod
    def _NewPublicKeyPoint(pub_key: Bip32PublicKey,
                           zl_bytes: bytes) -> IPoint:
        """
        Compute new public key point for public derivation.

        Args:
            pub_key (Bip32PublicKey object): Bip32PublicKey object
            zl_bytes (bytes)               : Leftmost Z 32-byte

        Returns:
            IPoint object: IPoint object
        """

        # Compute the new public key point: PKEY + 8ZL * G
        #zl_int = BytesUtils.ToInteger(zl_bytes[:28], endianness="little")
        zl_int = BytesUtils.ToInteger(
            Bip32PeikertEd25519KeyDerivator.trunc_256_minus_g_bits(zl_bytes),
            endianness="little",
        )
        return pub_key.Point() + ((zl_int * 8) * pub_key.Curve().Generator())
