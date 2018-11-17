"""
StorageServer and PublicKeyServer implementations.
"""


class StorageServer(object):
    """Simple implementation of a storage server using a key-value store.

    Exposes the get, put, and delete functions as defined in the specification.

    Remember, storage server is untrusted and can and will behave maliciously.
    Not this implementation though, but the one which will be used for grading.

    Your Client class will be initialized with a StorageServer object, through
    which you will access these methods.

    .. note::
        **Do not modify this class!** None of your changes will be used when
        we grade your implementation.
    """
    def __init__(self):
        self.kv = {}

    def get(self, id):
        """Retrieves the value stored at `id`

        :param str id: The id to get
        :returns: The value, or None if `id` does not exist in the store
        :rtype: str or None
        """
        if id not in self.kv:
            return None
        return self.kv[id]

    def put(self, id, value):
        """Stores `value` at `id`

        :param str id: The id to store `value` at
        :param str value: The value to store

        :returns: True, if the `put` succeeded

        :raises TypeError: If id or value are not strings
        """
        if not isinstance(id, str):
            raise TypeError("id must be a string")
        if not isinstance(value, str):
            print(value)
            raise TypeError("value must be a string")
        self.kv[id] = value
        return True

    def delete(self, id):
        """Deletes the given `id` from the server.

        :param str id: The id to delete
        """
        if id in self.kv:
            del self.kv[id]


class PublicKeyServer(object):
    """Simple implementation of a public key server.

    Exposes the put_public_key and get_public_key functions as defined in the
    specification.

    Remember, public key server is trusted and will operate as such during
    grading as well.

    Your Client class will be initialized with a PublicKeyServer object,
    through which you will access these methods.

    .. note::
        **Do not modify this class!** None of your changes will be used when
        we grade your implementation.
    """
    def __init__(self):
        self.sigkey = {}
        self.enckey = {}

    def put_signature_key(self, username, pubkey):
        """Set the public signature key for your `username`.

        .. note::
            **Must only be called once!**

        .. note::
            Students should use
            :meth:`base_client.BaseClient.generate_public_key_pairs` instead of
            calling this directly.

        :param str username: Your client's username
        :param pubkey: Your RSA public key
        :type pubkey: An RSA key object
        """
        self.sigkey[username] = pubkey

    def put_encryption_key(self, username, pubkey):
        """Set the public encryption key for your `username`.

        .. note::
            **Must only be called once!**

        .. note::
            Students should use
            :meth:`base_client.BaseClient.generate_public_key_pairs` instead of
            calling this directly.

        :param str username: Your client's username
        :param pubkey: Your ElGamal public key
        :type pubkey: An ElGamal key object
        """
        self.enckey[username] = pubkey


    def get_signature_key(self, username):
        """Get the public signature key associated with `username`.

        :param str username: The username to lookup the public key of.
        :returns: The RSA key object containing the public key, or `None` if
            the user does not have a key registered with the PublicKeyServer.
        """
        if username in self.sigkey:
            return self.sigkey[username]
        return None


    def get_encryption_key(self, username):
        """Get the public encryption key associated with `username`.

        :param str username: The username to lookup the public key of.
        :returns: The ElGamal key object containing the public key, or `None` if
            the user does not have a key registered with the PublicKeyServer.
        """
        if username in self.enckey:
            return self.enckey[username]
        return None
