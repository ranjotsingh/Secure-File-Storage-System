class IntegrityError(RuntimeError):
    """Error to raise whenever an integrity error is encountered."""
    pass


class BaseClient(object):
    """Base class to build a file store client off of.

    You should build your secure client implementation in ``client.py``,
    subclassing off of this base class.
    """
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        """Initializes a new BaseClient object.

        This sets the username, storage server, public key server, crypto
        object, and private key for the client.

        Your Client subclass should call `super().__init__()` to call this
        initializer, or copy this code as needed.

        :param StorageServer storage_server: A StorageServer object.
        :param PublicKeyServer public_key_server: A PublicKeyServer object.
        :param Crypto crypto_object: A Crypto object (see crypto.py and
            InsecureClient for how this is used)
        :param str username: The username for this client. You may assume that
            usernames consist solely of lower-case letters (``[a-z]+``).
        """
        self.username = username
        self.storage_server = storage_server
        self.pks = public_key_server
        self.crypto = crypto_object
        (_rsa_key, _elg_key) = self.generate_public_key_pairs()
        self.elg_priv_key = _elg_key
        self.rsa_priv_key = _rsa_key

    def generate_public_key_pairs(self):
        """Create two asymmetric key pairs for this client; one for encryption
        and the other for signatures.

        .. note::
            You should call this exactly once in the initialization of your
            client. This method will automatically put the keys to the public
            key server, and save a copy of your private keys to the filesystem.
            This is the only persistent state that your client can use (that
            is, you can assume that for the same username, a client will have
            the same public/private keys even if restarted).

        If the keys already exist, this will load them from the filesystem.

        If the keys do not exist, this will create two new key pairs, upload
        the public keys to the Public Key Server, and save a copy of the
        private keys to the filesystem (as ``keys/<username>.pem`` for
        signature key and  as ``keys/<username>.cs161_json_key`` for
        encryption key).

        The signature key is an RSA key with 2048-bit modulus. The first
        returned value is an RSA key object containing both the public
        and the private key. You can pass this object to signature related
        functions that take a public key or private key. See PyCrypto
        documentation for `_RSAobj <https://pythonhosted.org/pycrypto/Crypto.PublicKey.RSA._RSAobj-class.html>`_

        The encryption key is an ElGamal key over a prime field with 2048-bits.
        The second returned value is an ElGamal key object that you can pass
        to asymmetric encryption related functions. See PyCrypto documentation
        for `ElGamalobj <https://pythonhosted.org/pycrypto/Crypto.PublicKey.ElGamal.ElGamalobj-class.html>`_

        :returns: (k1, k2), where k1 is an RSA key object containing both the
            public and private key; k2 is an ElGamal key object containing both
            the public and private key.
        """

        rsa_key = self.crypto._load_keyfile_rsa(self.username)
        elg_key = self.crypto._load_keyfile_elg(self.username)

        if rsa_key and elg_key:
            rsa_pub_key = rsa_key.publickey()
            elg_pub_key = elg_key.publickey()
        else:
            # First remove any files that may exist
            self.crypto._remove_keyfile(self.username)

            # generate new keys
            rsa_pub_key, rsa_key = self.crypto._gen_rsa_keypair(2048)
            self.crypto._save_keyfile_rsa(self.username, rsa_key)

            elg_pub_key, elg_key = self.crypto._gen_elg_keypair(2048)
            self.crypto._save_keyfile_elg(self.username, elg_key)

        # update key server
        self.pks.put_signature_key(self.username, rsa_pub_key)
        self.pks.put_encryption_key(self.username, elg_pub_key)

        return rsa_key, elg_key


    def upload(self, name, value):
        """Places the string `value` at `name` so that future calls to
        ``download`` for `name` return `value`.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        :param str name: The name of the file. You can assume file names are
            alphanumeric (that is, they match the regex ``[A-Za-z0-9]+``).
        :param str value: The value to upload.
        """
        raise NotImplementedError

    def download(self, name):
        """Returns the last value stored at `name` by the owner or anyone with
        whom it has been shared, or `None` if the file does not exist.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        :param str name: The name of the file. You can assume file names are
            alphanumeric (that is, they match the regex ``[A-Za-z0-9]+``).
        :returns: A string, the last value stored at `name`, or None if the
            file does not exist.
        """
        raise NotImplementedError

    def share(self, user, name):
        """Share a file `name` with `user`.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        ``share`` and ``receive_share`` work together as follows:

        ::

           msg = alice.share("bob", filename)
           bob.receive_share("alice", newfilename, msg)

        :param str user: The username of the user you are sharing with.
        :param str name: The name of the file you are sharing with `user`.
        :returns: A string, containing the message to give to `user` through an
            out-of-band channel that will let them access the file.
        """
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        """Receive a share message generated by the `share` method of another
        client with username `from_username`.
        Once this is done, the client calling this method should now be able to
        access the shared file under the name `newname`.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        ``share`` and ``receive_share`` work together as follows:

        ::

           msg = alice.share("bob", filename)
           bob.receive_share("alice", newfilename, msg)

        :param str from_username: The username of the sharing client.
        :param str newname: The new filename under which this client will
            access the file.
        :param str message: The message generated by the sharing client's
            `share` method.

        """
        raise NotImplementedError

    def revoke(self, user, name):
        """Revokes `user`'s access to the file `name`.

        `user` should not be able to observe new updated to `name`, and should
        not be able update it.

        Anyone with whom `user` shared this file should also be revoked.

        You may not send any messages during revocation.

        A secure client implementation of this method should meet all of the
        required properties listed in the project specification.

        :param str user: The username of the user whose access will be revoked
        :param str name: The name of the file
        """
        raise NotImplementedError
