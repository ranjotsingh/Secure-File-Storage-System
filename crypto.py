"""
Crypto functions for implementing your secure file store client.
"""

import os
from binascii import hexlify, unhexlify

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Cipher.blockalgo import MODE_ECB, MODE_CBC, MODE_CFB, MODE_OFB, \
    MODE_CTR

from Crypto.Hash import HMAC
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA, ElGamal
from Crypto import Random
from Crypto.Random.random import randint
from Crypto.Util import Counter, number

import json # for storing ElGamal keys; don't use in real-world.

# Set of block ciphers you can pick from.
name_to_cipher = {
    'AES': AES.new
}

# Set of hash functions you can choose from.
name_to_hash = {
    'SHA256': SHA256.SHA256Hash
}

# Set of block cipher modes of operation you can choose from.
name_to_mode = {
    'ECB': MODE_ECB,
    'CBC': MODE_CBC,
    'CFB': MODE_CFB,
    'OFB': MODE_OFB,
    'CTR': MODE_CTR
}


class CryptoError(RuntimeError):
    """An error which will be raised if anything happens wrong in any of the
    cryptographic methods.

    A CryptoError is raised when a function is called with invalid parameters
    (such as an invalid ciphername), or is called with the wrong types of
    arguments (not string for message, ciphertext, or symmetric key), or when
    an operation fails (such as trying to unpad an invalid padding).
    """
    pass


class Crypto(object):
    """A class grouping together all of the Crypto API functions.

    We provide a set of symmetric key ciphers, block cipher modes of operation,
    and cryptographic hash functions to select from. You must pass the name of
    the cipher, mode, or function you desire to the respective methods in the
    API. These names are defined in the dictionaries ``name_to_cipher``,
    ``name_to_mode``, and ``name_to_hash``.

    Ciphers:
        'AES'

        See the PyCrypto `Cipher package
        <https://pythonhosted.org/pycrypto/Crypto.Cipher-module.html>`_
        for more details.

    Modes:
        'ECB', 'CBC', 'CFB', 'OFB', 'CTR'

        See the PyCrypto `blockalgo module
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html>`_
        for more details.

    Hash Functions:
        'SHA256'

        See the PyCrypto `Hash package
        <https://pythonhosted.org/pycrypto/Crypto.Hash-module.html>`_
        for more details.
    """
    def __init__(self):
        """You should never have to create a new Crypto object yourself from
        within the Client class. You should assume that it will be passed to
        the Client's constructor automatically. You should store it and use it."""
        pass

    #####################
    # Utility Functions #
    #####################
    def get_random_bytes(self, n):
        """Returns n bytes of cryptographically-strong randomness, as a
        hex-encoded string.

        Uses the underlying PyCrypto Random package. Under the hood, this will
        read random bytes from the OS-provided RNG. On POSIX, this is
        /dev/urandom. On Windows, this is CryptGenRandom.

        This method is secure for cryptographic use. You should use it when you
        need a secure source of randomness. Or, you can simply use it always
        when you need randomness.

        :params int n: Number of random bytes to generate.
        :returns: n cryptographically-strong random bytes, as a hex-encoded
            string
        :rtype: str
        """
        return _bytes_to_hex(Random.new().read(n))

    def new_counter(self, nbits, initial_value=1, prefix='', suffix=''):
        """A fast counter implementation for use with block ciphers in CTR mode.

        See the PyCrypto `Counter module
        <https://pythonhosted.org/pycrypto/Crypto.Util.Counter-module.html>`_
        for more information about the underlying implementation.

        To use with :meth:`crypto.Crypto.symmetric_encrypt` and
        :meth:`crypto.Crypto.symmetric_decrypt`, use this method to create a
        new Counter object and pass it as the `counter` argument.

        :param int nbits: Length of the desired counter, in bits. It must be a
            multiple of 8.
        :param int initial_value: The initial value of the counter. Default
            value is 1.
        :param str prefix: The constant prefix of the counter block.
            A hex-encoded string of bytes.
            By default, no prefix is used.
        :param str suffix: The constant suffix of the counter block.
            A hex-encoded string of bytes.
            By default, no suffix is used.
        :returns: A new stateful counter callable object.
        """
        prefix_bytes = _hex_to_bytes(prefix)
        suffix_bytes = _hex_to_bytes(suffix)
        return Counter.new(nbits, initial_value=initial_value,
                           prefix=prefix_bytes, suffix=suffix_bytes)

    ##############################
    # Symmetric crypto functions #
    ##############################

    def symmetric_encrypt(self, message, key, cipher_name=None,
                          mode_name='ECB', IV=None, iv=None,
                          counter=None, ctr=None,
                          segment_size=None, **kwargs):
        """Encrypt data with the key for the chosen parameters.

        You must select a cipher name from the table name_to_cipher.
        You must provide all parameters required for your chosen cipher.

        This function will automatically pad the message to a multiple of the
        block size.

        Remember, symmetric keys can be simply random bytes.

        See PyCrypto `BlockAlgo class
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo.BlockAlgo-class.html>`_
        for more information about the underlying implementation.

        :param str message: The piece of data to encrypt.
        :param str key: The secret key to use in the symmetric cipher.
            Length varies depending on the cipher chosen. A string containing
            the hex-encoded bytes of the key.
        :param str cipher_name: Cipher to use, chosen from name_to_cipher
            table.
        :param str mode_name: Block mode of operation to use, chosen from
            name_to_mode table. Defaults to EBC mode.
        :param str IV: The initialization vector to use for encryption
            or decryption. It is ignored for MODE_ECB and MODE_CTR.
            For all other modes, it must be block_size bytes longs. Optional --
            when not present it will be given a default value of all zeroes.
            A string containing the hex-encoded bytes of the IV.
        :param callable counter: (Only MODE_CTR) A stateful function that
            returns the next counter block, which is a byte string of
            block_size bytes.
            It is recommended to use :meth:`crypto.Crypto.new_counter` to
            create a new counter object to pass as the parameter.
        :param int segment_size: (Only MODE_CFB) The number of bits the
            plaintext and ciphertext are segmented in.
            It must be a multiple of 8. If 0 or not specified, it will be
            assumed to be 8.

        :returns: the encrypted data
        :rtype: str, as long as the plaintext

        :raises CryptoError: If the cipher or mode name is invalid, or if
            message or key are not a strings.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if cipher_name not in name_to_cipher:
            raise CryptoError("Cipher not known " + str(cipher_name))
        if mode_name not in name_to_mode:
            raise CryptoError("Mode not known " + str(cipher_name))
        if IV:
            kwargs['IV'] = _hex_to_bytes(IV)
        elif iv:
            kwargs['IV'] = _hex_to_bytes(iv)
        else:
            kwargs['IV'] = b'0'*16
        if counter:
            kwargs['counter'] = counter
        elif ctr:
            kwargs['counter'] = ctr
        if segment_size:
            kwargs['segment_size'] = segment_size

        if mode_name not in ['CBC', 'CFB', 'OFB']:
            kwargs.pop('IV', None)
        if mode_name !='CTR':
            kwargs.pop('counter', None)

        message_bytes = _string_to_bytes(message)
        message_bytes = self._pad(message_bytes, 16)
        key_bytes = _hex_to_bytes(key)
        mode = name_to_mode[mode_name]
        cipher = name_to_cipher[cipher_name](key_bytes, mode, **kwargs)
        return _bytes_to_hex(cipher.encrypt(message_bytes))

    def symmetric_decrypt(self, ciphertext, key, cipher_name=None,
                          mode_name='ECB', IV=None, iv=None,
                          counter=None, ctr=None,
                          segment_size=None, **kwargs):
        """Decrypt data with the key for the chosen parameters.

        You must select a cipher name from the table name_to_cipher.
        You must provide all parameters required for your chosen cipher.

        This function will automatically unpad the decrypted message.

        See PyCrypto `BlockAlgo class
        <https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo.BlockAlgo-class.html>`_
        for more information about the underlying implementation.

        :param str ciphertext: The piece of data to decrypt.
        :param str key: The secret key to use in the symmetric cipher.
            Length varies depending on the cipher chosen. A string containing
            the hex-encoded bytes of the key.
        :param str cipher_name: Cipher to use, chosen from name_to_cipher
            table.
        :param str mode_name: Block mode of operation to use, chosen from
            name_to_mode table. Defaults to EBC mode.
        :param str IV: The initialization vector to use for encryption
            or decryption. It is ignored for MODE_ECB and MODE_CTR.
            For all other modes, it must be block_size bytes longs. Optional --
            when not present it will be given a default value of all zeroes.
            A string containing the hex-encoded bytes of the IV.
        :param callable counter: (Only MODE_CTR) A stateful function that
            returns the next counter block, which is a byte string of
            block_size bytes.
            It is recommended to use :meth:`crypto.Crypto.new_counter` to
            create a new counter object to pass as the parameter.
        :param int segment_size: (Only MODE_CFB) The number of bits the
            plaintext and ciphertext are segmented in.
            It must be a multiple of 8. If 0 or not specified, it will be
            assumed to be 8.

        :returns: the decrypted data
        :rtype: str

        :raises CryptoError: If the cipher or mode name is invalid, or the
            unpadding fails, or if ciphertext or key are not a strings.
        """
        if not isinstance(ciphertext, str):
            raise CryptoError("Ciphertext must be a string")
        if cipher_name not in name_to_cipher:
            raise CryptoError("Cipher not known")
        if mode_name not in name_to_mode:
            raise CryptoError("Mode not known")
        if IV:
            kwargs['IV'] = _hex_to_bytes(IV)
        elif iv:
            kwargs['IV'] = _hex_to_bytes(iv)
        else:
            kwargs['IV'] = b'0'*16
        if counter:
            kwargs['counter'] = counter
        elif ctr:
            kwargs['counter'] = ctr
        if segment_size:
            kwargs['segment_size'] = segment_size

        if mode_name not in ['CBC', 'CFB', 'OFB']:
            kwargs.pop('IV', None)
        if mode_name !='CTR':
            kwargs.pop('counter', None)

        ciphertext_bytes = _hex_to_bytes(ciphertext)
        key_bytes = _hex_to_bytes(key)
        mode = name_to_mode[mode_name]
        cipher = name_to_cipher[cipher_name](key_bytes, mode, **kwargs)
        message = self._unpad(cipher.decrypt(ciphertext_bytes))
        return _bytes_to_string(message)

    def cryptographic_hash(self, message, hash_name=None):
        """Generates the printable digest of message using the named hash function.

        See the PyCrypto `HashAlgo class
        <https://pythonhosted.org/pycrypto/Crypto.Hash.hashalgo.HashAlgo-class.html>`_
        for more information about the underlying implementation.

        :param str message: The message to hash.
        :param str hash_name: Hash to use, chosen from name_to_hash table.

        :returns: The digest, a string of 2*digest_size characters.
            Contains only hexadecimal digits.
        :rtype: str

        :raises CryptoError: If name of hash is invalid, or message is not a
            string.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if hash_name not in name_to_hash:
            raise CryptoError("Hash not known.")
        message_bytes = _string_to_bytes(message)
        return name_to_hash[hash_name](message_bytes).hexdigest()

    def message_authentication_code(self, message, key, hash_name=None):
        """Generates the printable MAC of the message.

        This uses an HMAC, so you must provide the hash function to use, chosen
        from the name_to_hash table.

        See the PyCrypto `HMAC module
        <https://pythonhosted.org/pycrypto/Crypto.Hash.HMAC-module.html>`_
        for more information about the underlying implementation.

        :param str message: The message to authenticate.
        :param str key: Key for the MAC. A string containing
            the hex-encoded bytes of the key.
        :param str hash_name: Hash to use, chosen from name_to_hash table.

        :returns: The authentication tag, a string of 2*digest_size bytes.
            Contains only hexadecimal digits.
        :rtype: str

        :raises CryptoError: If name of hash is invalid, or if the key or
            message are not strings.
        """
        if not isinstance(key, str):
            raise CryptoError("Key must be a string")
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if hash_name not in name_to_hash:
            raise CryptoError("Hash not known")
        hashAlgo = name_to_hash[hash_name]
        key_bytes = _hex_to_bytes(key)
        message_bytes = _string_to_bytes(message)
        return HMAC.HMAC(key_bytes, msg=message_bytes,
                         digestmod=hashAlgo()).hexdigest()

    ###############################
    # Asymmetric crypto functions #
    ###############################

    def asymmetric_encrypt(self, message, public_key):
        """Encrypt a message using El Gamal encryption scheme.

        :param message: The message to encrypt. The message must be numerically
            smaller than the modulus of the prime field.
        :type message: str or bytes
        :param public_key: The public key to encrypt with.
        :type public_key: An ElGamal Key object

        :returns: The ciphertext in which the message is encrypted.
        :rtype: str

        :raises CryptoError: If message is not a string, or if public_key
            is not an ElGamal key object.
        :raises ValueError: If the key length is not sufficiently long to
            deal with the given message.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")

        if not isinstance(public_key, ElGamal.ElGamalobj):
            raise CryptoError("public_key is not an ElGamal key")

        message_bytes = _string_to_bytes(message)
        K = randint(1, public_key.p-2)
        (c1, c2) = public_key.encrypt(message_bytes, K)

        _dict = {'c1': _bytes_to_hex(c1), 'c2': _bytes_to_hex(c2)}
        return json.dumps(_dict)


    def asymmetric_decrypt(self, ciphertext, private_key):
        """Decrypt ciphertext that has been encrypted using ElGamal encryption

        :param str ciphertext: The ciphertext that contains the message
            to recover.
        :param private_key: The private key to decrypt with.
        :type private_key: An ElGamal key object

        :returns: The original message
        :rtype: str

        :raises CryptoError: If private_key isn't an ElGamal private key, or
            if decryption fails.
        """
        if not isinstance(private_key, ElGamal.ElGamalobj):
            raise CryptoError("Not an ElGamal key")

        if not private_key.has_private():
            raise CryptoError("Not a private key!!")

        try:
            _dict = json.loads(ciphertext)
            _cipher = (_hex_to_bytes(_dict['c1']), _hex_to_bytes(_dict['c2']))
            return _bytes_to_string(private_key.decrypt(_cipher))
        except:
            raise CryptoError("Decryption failed")


    def asymmetric_sign(self, message, private_key):
        """Produce the PKCS#1 PSS RSA signature of the message.

        See the PyCrypto `PKCS1_PSS module
        <https://pythonhosted.org/pycrypto/Crypto.Signature.PKCS1_PSS-module.html>`_
        for more information about the underlying implementation.
        PKCS#1 PSS is a secure signature scheme.

        :param str message: The message to sign.
        :param private_key: The private key to sign with.
        :type private_key: An RSA key object

        :returns: The signature.
        :rtype: str

        :raises CryptoError: If message is not a string, or if private_key
            is not an RSA key object.
        :raises ValueError: If the RSA key length is not sufficiently long to
            deal with the given hash algorithm (SHA256).
        :raises TypeError: If the RSA key has no private half.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")

        if not isinstance(private_key, RSA._RSAobj):
            raise CryptoError("private_key is not an RSA key")

        h = SHA256.new()
        h.update(_string_to_bytes(message))
        signer = PKCS1_PSS.new(private_key)
        signature = signer.sign(h)
        return _bytes_to_hex(signature)

    def asymmetric_verify(self, message, signature, public_key):
        """Verify that a PKCS#1 PSS RSA signature is authentic.

        See the PyCrypto `PKCS1_PSS module
        <https://pythonhosted.org/pycrypto/Crypto.Signature.PKCS1_PSS-module.html>`_
        for more information about the underlying implementation.

        :param str message: The original message.
        :param str signature: The signature to be verified.
        :param public_key: The public key of the signer.
        :type public_key: An RSA key object

        :returns: True if verification is correct. False otherwise.
        :rtype: bool

        :raises CryptoError: If message or signature are not strings, or
            if public_key is not an RSA public key.
        """
        if not isinstance(message, str):
            raise CryptoError("Message must be a string")
        if not isinstance(signature, str):
            raise CryptoError("Signature must be a string")
        if not isinstance(public_key, RSA._RSAobj):
            raise CryptoError("public_key must be an RSA public key")

        try:
            h = SHA256.new()
            h.update(_string_to_bytes(message))
            verifier = PKCS1_PSS.new(public_key)
            status = verifier.verify(h, _hex_to_bytes(signature))
            return status
        except:
            return False

    #########################################
    #           Private functions           #
    # STUDENTS: You won't need to use these #
    #########################################


    # precomputed primes of form p=2*q+1 (where q is also prime)
    __safe_primes = {
        512 : "0xdcf68b426714a9b22e6376e06248f60409faf1" + \
                    "1b7ce0333aea27b9dc46ab3ca70524b370e26184" + \
                    "6ea4a4886bdaf129725f241eab3e82a2ae0bbbda" + \
                    "bca5e3cd3f",
        768 : "0xb3e9cbb4d148f926dc6519681d86ac24ebf14b" + \
                    "8944f18cbcbcb98e2db6f2f18b16bb8152f81cea" + \
                    "c552ad5ea2843def04b31338e215a562ce63024a" + \
                    "130c6685970460584e8ed515599ad2873352346a" + \
                    "f6609dd93436d0983cd09e0593ee27fc73",
        1024 : "0xa30dbb9d81bb7879fbba2be4b5aca6800dc0e8" + \
                    "4b33ecbd317f22376277e43476cf634762bbc45e" + \
                    "875c42d8b29121a27fc5f80b13dca8fc5bec4618" + \
                    "a0da5150f4028d33be73d34922ae3210dbb0631d" + \
                    "971479df465c18bdf2e3ad83a66694ac5760af1a" + \
                    "ad3bd7d7083722cde3d11ca9d20fef0eda8117db" + \
                    "4e1aedd3143f07deeb",
        2048 : "0xd4896ea5cb5d0859e258cbc5c96ca44f8a6191" + \
                    "59116dffeb5adca0d5bf310cf1495f69fd247955" + \
                    "6d5972e05c98d8f26d986aaff4e6e8de0df30146" + \
                    "ce22c5d4bf6d8183bb6f6aa2a847676b202d0559" + \
                    "eb34caef79e18d2e6a509e637ed614f66901849b" + \
                    "a69d2f26f62147f0cb68e1bf692fce234a07c4bf" + \
                    "d26ac7334fbf9564e5139e9e88be9364188af15d" + \
                    "de4ec91befc8eccc0ee82cb3032d4731db1cc986" + \
                    "a13a9b23e63072d65b49a8cac32e243164471ef0" + \
                    "91de8c160f51d33abca05c0c5a8ec8627f12e97a" + \
                    "e7e2294d4b3fbac45d0ac254eaf159e36a7b0137" + \
                    "9f3e9d2ad06d5d163a5d183d01d696b0da4238fb" + \
                    "aac9b8923b3c853b3d28ed1146f6fea9df",
        3072 : "0xe21a1601219a68db6b28acfc415c398b912000" + \
                    "a626096d4826a4397da6dba60d9ce04757581161" + \
                    "ea9570d1a45646e26a5e5dba857d3bcadb649c88" + \
                    "580d80cc7ddda2c7ea84c21f2a18cbb15f12c076" + \
                    "97bd3159f560fadcc056f2c223b0d578a0fe3412" + \
                    "069f62325593d561764a9cb17b5567a17d356706" + \
                    "1e85f504890236fa6ad6ad6b572b6d502ff4a505" + \
                    "0eb0f606da337735ef1119f25075c142ae4bb798" + \
                    "531409e9e84dee6f4cf607a3549806cf15d6785e" + \
                    "b6e6fc14c0dacd60cc30903f7ac05bf72f20076a" + \
                    "358e6a586ec1c85d95cf98bc22fc702643da32a7" + \
                    "645e14a840c5d062b6b727db2d5cf9122b415db7" + \
                    "a6b8af4cdc4f5d4683114159425e5f28e5b7d7f3" + \
                    "0f59809ef04d1cd5200c0966223d4804b5eef2fc" + \
                    "903ac1c0b9c1f3ead565759028526c217d5b43c4" + \
                    "2f1f147462fb16ddd035c48d8b98931b3137fd73" + \
                    "e0ed1497353c52a2641127f108323b6811d6f57b" + \
                    "bed2c1f3465c8559460f67fcca8a7d8110a7f50e" + \
                    "99bf04a48fc979348f42ad54af23e27c914edb18" + \
                    "77da2079db"
    }

    def __ElGamal_generate(self, bits, randfunc):
        """Randomly generate a new ElGamal key but with pre-computed group.

        Based on public domain code from PyCrypto
        - ElGamal.py : ElGamal encryption/decryption and signatures
        - Part of the Python Cryptography Toolkit
        - Originally written by: A.M. Kuchling

        The key will be safe for use for both encryption and signature
        (although it should be used for **only one** purpose).

        :Parameters:
            bits : int
                Key length, or size (in bits) of the modulus *p*.
                Recommended value is 2048.
            randfunc : callable
                Random number generation function; it should accept
                a single integer N and return a string of random data
                N bytes long.

        :attention: You should always use a cryptographically secure random
            number generator, such as the one defined in the
            ``Crypto.Random`` module; **don't** just use the current time
            and the ``random`` module.

        :Return: An ElGamal key object (`ElGamalobj`).
        """

        # Creating ElGamal keys is slow, especially with PyCrypto. The
        # key-generation is done over a cyclic group created based on a safe
        # prime.

        # A safe prime is a prime `p` of the form `p = 2*q + 1` where `q` is
        # *also* a prime; computing this can be as slow as taking ~3-5 minutes
        # for a 2048-bit number and upwards of an hour for a 4096-bit number.

        # However, we can pre-compute the prime `p` for common key-lengths
        # and use that instead, without impacting security of the scheme.

        obj=ElGamal.ElGamalobj()

        # Generate a safe prime p
        # See Algorithm 4.86 in Handbook of Applied Cryptography

        ## if using some commonly used key-lengths, use a pre-computed p
        if bits in self.__safe_primes:
            obj.p = int(self.__safe_primes[bits], 16)
            q = (obj.p-1)//2
        else:
            # no-precomputed value available. Default to creating new prime
            # XXX This is very slow for large key-sizes.
            while 1:
                q = bignum(getPrime(bits-1, randfunc))
                obj.p = 2*q+1
                if number.isPrime(obj.p, randfunc=randfunc):
                    break
        # Generate generator g
        # See Algorithm 4.80 in Handbook of Applied Cryptography
        # Note that the order of the group is n=p-1=2q, where q is prime
        while 1:
            # We must avoid g=2 because of Bleichenbacher's attack described
            # in "Generating ElGamal signatures without knowning the secret key",
            # 1996
            #
            obj.g = number.getRandomRange(3, obj.p, randfunc)
            safe = 1
            if pow(obj.g, 2, obj.p)==1:
                safe=0
            if safe and pow(obj.g, q, obj.p)==1:
                safe=0
            # Discard g if it divides p-1 because of the attack described
            # in Note 11.67 (iii) in HAC
            if safe and divmod(obj.p-1, obj.g)[1]==0:
                safe=0
            # g^{-1} must not divide p-1 because of Khadir's attack
            # described in "Conditions of the generator for forging ElGamal
            # signature", 2011
            ginv = number.inverse(obj.g, obj.p)
            if safe and divmod(obj.p-1, ginv)[1]==0:
                safe=0
            if safe:
                break
        # Generate private key x
        obj.x=number.getRandomRange(2, obj.p-1, randfunc)
        # Generate public key y
        obj.y = pow(obj.g, obj.x, obj.p)
        return obj

    def __ElGamal_exportKey(self, key, format='CS161'):
        """Export this ElGamal key in a custom CS161 format

        :params str format: The format of the key, supported value is 'CS161'.
        :returns: a string that represents the serialzed key in requested
            format.
        :rtype: str
        """

        key_dict = key.__dict__

        if format=='CS161':
            return _string_to_bytes(json.dumps(key_dict))

        raise CryptoError("Unknown format specified!")


    def __ElGamal_importKey(self, extern_key):
        """Import an ElGamal key (public or private), encoded in either PEM
        or DER form.

        :params str extern_key: The key to import, encoded as a string
        :returns: an ElGamalobj representing a key
        :rtype: ElGamalobj
        """

        try:
            key_dict = json.loads(_bytes_to_string(extern_key))
            _tup = [key_dict['p'], key_dict['g'], key_dict['y']]
            if 'x' in key_dict:
                _tup.append(key_dict['x'])
            return ElGamal.construct(tuple(_tup))

        except:
            raise CryptoError("Can not parse key")

    def _gen_rsa_keypair(self, size):
        key = RSA.generate(size)
        return key.publickey(), key

    def _gen_elg_keypair(self, size):
        key = self.__ElGamal_generate(size, Random.new().read)
        return key.publickey(), key

    def _save_keyfile_rsa(self, username, private_key):
        if not os.path.exists("keys/"):
            os.mkdir("keys/")
        keyfile = os.path.join("keys", username + ".pem")
        with open(keyfile, 'wb') as f:
            f.write(private_key.exportKey(format='PEM'))
        return True

    def _load_keyfile_rsa(self, username):
        keyfile = os.path.join("keys", username + ".pem")
        private_key = None
        if os.path.exists(keyfile):
            with open(keyfile, 'rb') as f:
                content = f.read()
                private_key = RSA.importKey(content)
        return private_key

    def _save_keyfile_elg(self, username, private_key):
        if not os.path.exists("keys/"):
            os.mkdir("keys/")
        keyfile = os.path.join("keys", username + ".cs161_json_key")
        with open(keyfile, 'wb') as f:
            f.write(self.__ElGamal_exportKey(private_key))
        return True

    def _load_keyfile_elg(self, username):
        keyfile = os.path.join("keys", username + ".cs161_json_key")
        private_key = None
        if os.path.exists(keyfile):
            with open(keyfile, 'rb') as f:
                content = f.read()
                private_key = self.__ElGamal_importKey(content)
        return private_key

    def _remove_keyfile(self, username):
        keyfile = os.path.join("keys", username + ".pem")
        if os.path.exists(keyfile):
            return os.remove(keyfile)
        keyfile = os.path.join("keys", username + ".cs161_json_key")
        if os.path.exists(keyfile):
            return os.remove(keyfile)


    def _pad(self, message, boundary=16):
        """PKCS7 padding

        Pads message's length to a multiple of the boundary size.

        Parameters:
          * message (bytes): The data to pad.
          * boundary (integer): The block size to pad.

        Returns:
          * A string of the message + the padding.
        """
        assert boundary < 256
        padding = boundary - len(message) % boundary
        out = bytes(range(1, padding + 1))
        return message + out

    def _unpad(self, message):
        """PKCS7 padding

        Unpads a message padded from the pad function.

        Parameters:
          * message (bytes): The data to unpad.

        Returns:
          * The original message without the padding.
        """
        skip = message[-1]
        for i in range(1, skip+1):
            if message[-i] != skip-i+1:
                raise CryptoError("Padding is invalid")
        return message[:-skip]


def _bytes_to_hex(b):
    return _bytes_to_string(hexlify(b))


def _hex_to_bytes(s):
    return unhexlify(s)


def _bytes_to_string(b):
    return str(b, 'utf-8')


def _string_to_bytes(s):
    return bytes(s, 'utf-8')


###################
# crypto.py tests #
###################
if __name__ == "__main__":
    crypto = Crypto()

    print("Testing skey generation, saving, and loading")
    vkey, skey = crypto._gen_rsa_keypair(2048)
    crypto._save_keyfile_rsa("testuser", skey)
    skey_loaded = crypto._load_keyfile_rsa("testuser")
    assert skey == skey_loaded

    print("Testing ekey generation, saving, and loading")
    ekey, dkey = crypto._gen_elg_keypair(2048)
    crypto._save_keyfile_elg("testuser", dkey)
    dkey_loaded = crypto._load_keyfile_elg("testuser")
    assert dkey == dkey_loaded

    m1 = "testing message of medium length"

    print("Testing asymmetric encryption")
    c1 = crypto.asymmetric_encrypt(m1, ekey)
    assert crypto.asymmetric_decrypt(c1, dkey) == m1

    print("Testing signatures")
    s1 = crypto.asymmetric_sign(c1, skey)
    assert crypto.asymmetric_verify(c1, s1, vkey)

    print("Testing padding")
    m2 = "testing message of medium length"
    padded = crypto._pad(_string_to_bytes(m2), boundary=128)
    unpadded = _bytes_to_string(crypto._unpad(padded))
    assert unpadded == m2

    print("Testing symmetric operations")
    k2 = _bytes_to_hex(bytes(range(0, 16)))
    # m2padded = crypto.pad(m2, boundary=16)
    c2 = crypto.symmetric_encrypt(m2, k2, cipher_name='AES',
                                  mode_name='ECB')
    m3 = crypto.symmetric_decrypt(c2, k2, cipher_name='AES', mode_name='ECB')
    # m3 = crypto.unpad(b3)
    assert m3 == m2

    print("Testing hashes")
    h1 = crypto.cryptographic_hash(m1, hash_name='SHA256')
    assert h1 == "039047cbe56842c1de8f4cb1e5348ed297a5d9775d617384dafbd9a935668be6"

    print("Testing MACs")
    mac = crypto.message_authentication_code(m1, k2, hash_name='SHA256')

    print("Testing RNG")
    random_bytes = crypto.get_random_bytes(4096)

    print("Testing counters")
    ctr = crypto.new_counter(16)
    assert ctr() == b'\x00\x01'
    assert ctr() == b'\x00\x02'

    iv1 = _bytes_to_hex(bytes(range(0, 8)))
    ctr1 = crypto.new_counter(64, prefix=iv1)
    k3 = _bytes_to_hex(bytes(range(0, 16)))
    c1 = crypto.symmetric_encrypt(m2, k3, cipher_name='AES', mode_name='CTR',
                                  counter=ctr1)
    ctr2 = crypto.new_counter(64, prefix=iv1)
    p1 = crypto.symmetric_decrypt(c1, k3, cipher_name='AES', mode_name='CTR',
                                  counter=ctr2)
    assert p1 == m2

    crypto._remove_keyfile("testuser")
