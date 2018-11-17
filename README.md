# Secure File Storage Server

Secure file storage server that efficiently stores data primarily focused on protecting against malicious attackers

## Design of System

The main design of the system consists of each client having a symmetric encryption key k<sub>e</sub>, symmetric MAC key k<sub>m</sub>, and symmetric key k<sub>n</sub> for filename confidentiality. Note that each time a file or message is uploaded, downloaded, sent, or received, it will be encrypted and authenticated by stated key pairs throughout this design document.

### How files are handled by server

- Whenever the server receives a file to be uploaded, the file is divided into blocks B of length 256 and a merkle-tree like structure encrypted by corresponding (k<sub>fe</sub>,k<sub>fm</sub>) (as described in sections below) is created from these blocks (stored at a random location)
- File nodes contain the random location and length of the files
- Tree nodes contain the corresponding HASH-SHA256 and the locations of left and right sub-nodes if they exist
