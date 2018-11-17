"""
Secure client
"""

from base_client import BaseClient, IntegrityError
from util import to_json_string, from_json_string

class Node:
    def __init__(self, hash_val, data, left, right, IV, location):
        self.hash_val = hash_val
        self.data = data
        self.left = left
        self.right = right
        self.IV = IV
        self.location = location

    def to_dict(self, enc_func, encryption_key, left_node=0, right_node=0):
        node = {
            'HV': self.hash_val,
            'D': None,
            'L': self.left.location if self.left else None,
            'R': self.right.location if self.right else None,
            'IV': None
        }
        if left_node != 0 and right_node != 0:
            node['L'] = left_node
            node['R'] = right_node
        if self.data:
            node['D'] = enc_func(self.data, encryption_key, cipher_name='AES', mode_name='CBC', IV=self.IV, iv=None, counter=None, ctr=None, segment_size=128)
            node['IV'] = self.IV
        return node

class Client(BaseClient):
    def node_init(self, value):
        blocks, nodes = [], []
        for i in range(0, len(value), 256):
            block = value[i:i+256]
            blocks.append(block)
            hash_val = self.crypto.cryptographic_hash(block, 'SHA256')
            IV = self.crypto.get_random_bytes(16)
            location = self.crypto.get_random_bytes(10)
            nodes.append(Node(hash_val, block, None, None, IV, location))
        while len(nodes) != 1:
            if len(nodes) % 2 == 1:
                nodes.append(None)
            temp = []
            for i in range(0, len(nodes), 2):
                location = self.crypto.get_random_bytes(10)
                left, right = nodes[i], nodes[i+1]
                if right:
                    temp.append(Node(self.crypto.cryptographic_hash(left.hash_val + right.hash_val, 'SHA256'), None, left, right, None, location))
                else:
                    temp.append(Node(self.crypto.cryptographic_hash(left.hash_val, 'SHA256'), None, left, right, None, location))
            nodes = temp
        node = nodes[0]
        return node

    def upload_node(self, node, encryption_key, mac_key, is_root):
        node_json = to_json_string(node.to_dict(self.crypto.symmetric_encrypt, encryption_key))
        if is_root:
            node_json = to_json_string({'node_json': node_json, 'mac': self.crypto.message_authentication_code(node.location + node_json, mac_key, hash_name='SHA256')})
        self.storage_server.put(node.location, node_json)
        if not node.data:
            if node.left:
                self.upload_node(node.left, encryption_key, mac_key, False)
            if node.right:
                self.upload_node(node.right, encryption_key, mac_key, False)

    def download_node(self, encryption_key, mac_key, location, is_root):
        main_node_json = self.storage_server.get(location)
        if not main_node_json:
            raise IntegrityError
        try:
            main_node = from_json_string(main_node_json)
            if is_root:
                node_json, node_mac = main_node['node_json'], main_node['mac']
                main_node = from_json_string(node_json)
                if self.crypto.message_authentication_code(location + node_json, mac_key, hash_name='SHA256') != node_mac:
                    raise IntegrityError
            value = ''
            if main_node['D']:
                value += self.crypto.symmetric_decrypt(main_node['D'], encryption_key, cipher_name='AES',mode_name='CBC', IV=main_node['IV'], iv=None,counter=None, ctr=None, segment_size=128)
            if main_node['L']:
                value += self.download_node(encryption_key, mac_key, main_node['L'], False)
            if main_node['R']:
                value += self.download_node(encryption_key, mac_key, main_node['R'], False)
            if not is_root:
                return value
            else:
                return value, main_node['HV']
        except:
            raise IntegrityError

    def update_node(self, node, encryption_key, mac_key, location, is_root):
        main_node_json = self.storage_server.get(location)
        if not main_node_json:
            raise IntegrityError
        try:
            main_node = from_json_string(main_node_json)
            if is_root:
                main_node = from_json_string(main_node['node_json'])
            if node.hash_val != main_node['HV']:
                node_json = to_json_string(node.to_dict(self.crypto.symmetric_encrypt, encryption_key, main_node['L'], main_node['R']))
                if is_root:
                    node_json = to_json_string({'node_json': node_json, 'mac': self.crypto.message_authentication_code(location + node_json, mac_key, hash_name='SHA256')})
                if not self.storage_server.put(location, node_json):
                    raise IntegrityError
                if node.left:
                    self.update_node(node.left, encryption_key, mac_key, main_node['L'], False)
                if node.right:
                    self.update_node(node.right, encryption_key, mac_key, main_node['R'], False)
        except:
            raise IntegrityError

    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        fromserver = self.storage_server.get(username + "keys")
        sigfromserver = self.storage_server.get(username + "keysig")
        if not fromserver:
            keys = self.crypto.get_random_bytes(48)
            toserver = self.crypto.asymmetric_encrypt(keys, self.pks.get_encryption_key(self.username))
            sigtoserver = self.crypto.asymmetric_sign(toserver, self.rsa_priv_key)
            self.storage_server.put(username + "keys", toserver)
            self.storage_server.put(username + "keysig", sigtoserver)
        else:
            check = self.crypto.asymmetric_verify(fromserver, sigfromserver, self.pks.get_signature_key(self.username))
            if not check:
                raise IntegrityError
            keys = self.crypto.asymmetric_decrypt(fromserver, self.elg_priv_key)
        self.encryption_key = keys[:32]
        self.mac_key = keys[32:64]
        self.filename_key = keys[64:]

    def path_join(self, *strings):
        return '/'.join(strings)

    def encrypt_mac_store(self, id, value, encryption_key, mac_key):
        if id is None:
            return None
        IVgen = self.crypto.get_random_bytes(16)
        encrypted_file = self.crypto.symmetric_encrypt(value, encryption_key, cipher_name='AES', mode_name='CBC', IV=IVgen, iv=None, counter=None, ctr=None, segment_size=128)
        mac = self.crypto.message_authentication_code(IVgen + encrypted_file, mac_key, hash_name='SHA256')
        tosend = mac + IVgen + encrypted_file
        self.storage_server.put(id, tosend)

    def mac_check_decrypt(self, id, decryption_key, mac_key):
        encrypted_file = self.storage_server.get(id)
        if encrypted_file is None:
            return None
        mac = encrypted_file[:64]
        IV = encrypted_file[64:96]
        encrypted_contents = encrypted_file[96:]
        mac_check = self.crypto.message_authentication_code(IV + encrypted_contents, mac_key, hash_name='SHA256')
        if mac != mac_check:
            raise IntegrityError
        return self.crypto.symmetric_decrypt(encrypted_contents, decryption_key, cipher_name='AES',mode_name='CBC', IV=IV, iv=None,counter=None, ctr=None, segment_size=128)

    def upload_shared(self, data, value):
        id = data[:32]
        encryption_key_for_file = data[32:64]
        mac_key_for_file = data[64:96]
        data = self.mac_check_decrypt(id, encryption_key_for_file, mac_key_for_file)
        if data[:7] == "<share>":
            return self.upload_shared(data[7:], value)
        try:
            data = from_json_string(data)
        except:
            return self.encrypt_mac_store(id, value, encryption_key_for_file, mac_key_for_file)
        node = self.node_init(value)
        if data['length'] != len(value):
            self.upload_node(node, encryption_key_for_file, mac_key_for_file, True)
            data = to_json_string({'length': len(value), 'location': node.location})
            self.encrypt_mac_store(id, data, encryption_key_for_file, mac_key_for_file)
        else:
            self.update_node(node, encryption_key_for_file, mac_key_for_file, data['location'], True)

    def upload(self, name, value):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        decrypted_resp = self.mac_check_decrypt(keypath, self.encryption_key, self.mac_key)
        if not decrypted_resp: # New file
            rand = self.crypto.get_random_bytes(48)
            id = rand[:32]
            encryption_key_for_file = rand[32:64]
            mac_key_for_file = rand[64:]
            self.encrypt_mac_store(keypath, rand+name, self.encryption_key, self.mac_key)

            node = self.node_init(value)
            self.upload_node(node, encryption_key_for_file, mac_key_for_file, True)
            meta = to_json_string({'length': len(value), 'location': node.location})
            self.encrypt_mac_store(id, meta, encryption_key_for_file, mac_key_for_file)
        else: # File already exists, check signatures for keys and ID
            self.upload_shared(decrypted_resp, value)

    def download_shared(self, data):
        id = data[:32]
        encryption_key_for_file = data[32:64]
        mac_key_for_file = data[64:96]
        data = self.mac_check_decrypt(id, encryption_key_for_file, mac_key_for_file)
        if data is None:
            return None
        elif data[:7] == "<share>":
            return self.download_shared(data[7:])
        else:
            try:
                data = from_json_string(data)
            except:
                return data
            value, root_hash_val = self.download_node(encryption_key_for_file, mac_key_for_file, data['location'], True)
            node = self.node_init(value)
            if node.hash_val != root_hash_val:
                raise IntegrityError
            return value

    def download(self, name):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        decrypted_resp = self.mac_check_decrypt(keypath, self.encryption_key, self.mac_key)
        if decrypted_resp is None:
            return None
        return self.download_shared(decrypted_resp)

    def receive_share(self, from_username, newname, message):
        signature = message[:512]
        encrypted_share_data = message[512:]
        senders_sig_public = self.pks.get_signature_key(from_username)
        if not self.crypto.asymmetric_verify(encrypted_share_data, signature, senders_sig_public):
            raise IntegrityError
        decrypted_share_data = self.crypto.asymmetric_decrypt(encrypted_share_data, self.elg_priv_key)
        share_id = decrypted_share_data[:32]
        encryption_key_for_share = decrypted_share_data[32:64]
        mac_key_for_share = decrypted_share_data[64:]
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(newname, self.filename_key, hash_name = 'SHA256'))
        key_data = share_id + encryption_key_for_share + mac_key_for_share
        self.encrypt_mac_store(keypath, key_data+newname, self.encryption_key, self.mac_key)

    def share(self, user, name):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        decrypted_resp = self.mac_check_decrypt(keypath, self.encryption_key, self.mac_key)
        if decrypted_resp is None:
            return None
        id = decrypted_resp[:32]
        encryption_key_for_file = decrypted_resp[32:64]
        mac_key_for_file = decrypted_resp[64:96]
        share_data = "<share>" + id + encryption_key_for_file + mac_key_for_file
        rand = self.crypto.get_random_bytes(48)
        share_id = rand[:32]
        encryption_key_for_share = rand[32:64]
        mac_key_for_share = rand[64:]
        unencrypted_to_add_to_share_list = user + '/' + share_id + encryption_key_for_share + mac_key_for_share + ' '
        sharepath = self.username + "share_list" + keypath
        temp = self.mac_check_decrypt(sharepath, self.encryption_key, self.mac_key)
        if temp is not None:
            unencrypted_to_add_to_share_list = unencrypted_to_add_to_share_list + temp
        self.encrypt_mac_store(sharepath, unencrypted_to_add_to_share_list, self.encryption_key, self.mac_key)
        self.encrypt_mac_store(share_id, share_data, encryption_key_for_share, mac_key_for_share)
        to_send_to_user = share_id + encryption_key_for_share + mac_key_for_share
        # Encrypt with their public key, sign with our private key
        their_public = self.pks.get_encryption_key(user)
        encrypted_to_send_to_user = self.crypto.asymmetric_encrypt(to_send_to_user, their_public)
        signature = self.crypto.asymmetric_sign(encrypted_to_send_to_user, self.rsa_priv_key)
        return signature + encrypted_to_send_to_user

    def revoke(self, user, name):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        sharepath = self.username + "share_list" + keypath
        cur_share_list = self.mac_check_decrypt(sharepath, self.encryption_key, self.mac_key)
        if cur_share_list is None:
            return
        cur_share_list = cur_share_list[:len(cur_share_list) - 1]
        list_as_array = cur_share_list.split(' ')
        names = [elem.split('/')[0] for elem in list_as_array]
        data_to_index = [elem.split('/')[1] for elem in list_as_array]
        index_of_removal = names.index(user)
        data = data_to_index[index_of_removal]
        data_to_index.pop(index_of_removal)
        list_as_array.pop(index_of_removal)
        cur_share_list = ' '.join(list_as_array)
        cur_share_list = cur_share_list + ' '
        self.encrypt_mac_store(sharepath, cur_share_list, self.encryption_key, self.mac_key)
        ID_to_delete = data[:32]
        self.storage_server.put(ID_to_delete, "byebyebye")
        rand = self.crypto.get_random_bytes(48)
        new_id = rand[:32]
        new_encryption_key_for_file = rand[32:64]
        new_mac_key_for_file = rand[64:]
        original_file = self.download(name)
        self.encrypt_mac_store(keypath, rand+name, self.encryption_key, self.mac_key)
        self.encrypt_mac_store(new_id, original_file, new_encryption_key_for_file, new_mac_key_for_file)
        share_data = "<share>" + new_id + new_encryption_key_for_file + new_mac_key_for_file
        for elem in data_to_index:
            share_id = elem[:32]
            encryption_key_for_share = elem[32:64]
            mac_key_for_share = elem[64:]
            self.encrypt_mac_store(share_id, share_data, encryption_key_for_share, mac_key_for_share)
