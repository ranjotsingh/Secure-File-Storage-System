# Secure File Storage Server

Secure file storage server using PyCrypto that efficiently stores data primarily focused on protecting against malicious attackers

## Design of System

The main design of the system consists of each client having a symmetric encryption key k<sub>e</sub>, symmetric MAC key k<sub>m</sub>, and symmetric key k<sub>n</sub> for filename confidentiality. Note that each time a file or message is uploaded, downloaded, sent, or received, it will be encrypted and authenticated by stated key pairs throughout this design document.

### How files are handled by server

- Whenever the server receives a file to be uploaded, the file is divided into blocks B of length 256 and a merkle-tree like structure encrypted by corresponding (k<sub>fe</sub>,k<sub>fm</sub>) (as described in sections below) is created from these blocks (stored at a random location)
- File nodes contain the random location and length of the files
- Tree nodes contain the corresponding HASH-SHA256 and the locations of left and right sub-nodes if they exist

### Client wishes to upload a new file:

- Create two new keys (k<sub>fe</sub>,k<sub>fm</sub>), which will be used for encryption and authentication respectively for the individual file.
- Store the following data of the file at random location l<sub>1</sub>, encrypted and authenticated with (k<sub>fe</sub>,k<sub>fm</sub>) respectively using AES-CBC with random IV:
  - Root node of tree for the corresponding file to upload
- Store the following metadata of the file at &lt;username&gt;/HMAC-SHA256<sub>kn</sub> (filename), encrypted and authenticated with (k<sub>e</sub>,k<sub>m</sub>) respectively using AES-CBC with random IV:
  - ID of random location l<sub>1</sub>, where the contents of the file is stored
  - Encryption and authentication keys for file: (k<sub>fe</sub>,k<sub>fm</sub>)
  - Filename

### Client wishes to update a file:

- Encrypt each file’s nodes’ information using (k<sub>fe</sub>,k<sub>fm</sub>) and convert node to json string before storing at random location as described sections above
- Compare root node’s length to determine if the updated file is larger, in which case we reupload the file as if it was new, otherwise recursively compare hash values from the root node and move down the tree until hashes do not match and store new value accordingly while updating its hashes

### Client wishes to download a file

- Move down the requested file’s tree by decrypting and authenticating each block with correspond- ing (k<sub>fe</sub>,k<sub>fm</sub>) (as described in section above) from the root node
- Combine decrypted block data together as moving along nodes to return the original file as uploaded

### Client wishes to share a file with another client

- Create two new keys (k<sub>se</sub>, k<sub>sm</sub>), which will be used for encryption and authentication respectively for storing share metadata.
- Store the following share metadata of the file at random location l<sub>2</sub>, encrypted and authenticated with (k<sub>se</sub>,k<sub>sm</sub>) respectively using AES-CBC with random IV:
  - ID of random location l<sub>1</sub>, where the contents of the file is stored encryption and authentication keys for file: (k<sub>fe</sub>,k<sub>fm</sub>)
- Store the following list of share information of the file at username + share list + HMAC- SHA256<sub>kn</sub> (filename), encrypted and authenticated with (k<sub>e</sub>, k<sub>m</sub>) respectively using AES-CBC with random IV:
  - Username of who the client wishes to share with
  - ID of random location l<sub>2</sub>, where the share metadata is stored
  - Encryption and authentication keys for share metadata: (k<sub>se</sub>, k<sub>sm</sub>)
- Send a message from client such that whoever the client wishes to share with receives it
  - Message contains the following information, encrypted and authenticated with (R<sub>PB</sub>, S<sub>PV</sub>) respectively using AES-CBC with random IV, where R<sub>PB</sub> is the receiver’s public key and S<sub>PV</sub> is the sender’s private key:
    - ID of random location l<sub>2</sub>, where the share metadata is stored
    - Encryption and authentication keys for share metadata: (k<sub>se</sub>,k<sub>sm</sub>)
  - Using the information from the sent message, receiver stores the following data of the file at &lt;receiver username&gt;/HMAC-SHA256<sub>kn</sub> (newname):
    - ID of random location l<sub>2</sub>, where the share metadata is stored
    - Encryption and authentication keys for share metadata: (k<sub>se</sub>,k<sub>sm</sub>)
    - Newname

### Client wishes to revoke a user's permission to a file:

- Locate the list of share information at username + share list + HMAC-SHA256<sub>kn</sub> (filename)
  - Lookup the ID of the share metadata location l<sub>2</sub> and delete it and its information
  - Remove the entry of the user that we wish to revoke
- Create two new keys (k'<sub>fe</sub>, k'<sub>fm</sub>), which will be used for reencryption and reauthentication respectively for the individual file.
- Move the random location of the data l<sub>1</sub> to a new random location l'<sub>1</sub>
- Update the metadata so that it has the new l'<sub>1</sub>
- For every remaining entry in the list, update the share metadata so that it has the new l'<sub>1</sub> and
  the new keys (k'<sub>fe</sub>,k'<sub>fm</sub>)

### Client wishes to use a shared file:

- Recursively use the share metadata of shared file to decrypt the next share metadata until reaching the data location l<sub>1</sub> of the file
- Client can now download from and upload to this location l<sub>1</sub> to use the data of the shared file
