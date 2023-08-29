# Secure messenger

## Secure Messenger Smart Contract and Encryption

This repository provides an example of a secure messaging smart contract built on Ethereum using Solidity and encryption techniques. The contract allows two participants to exchange encrypted messages while ensuring that only the intended recipients can decrypt and read the messages.

### SecureMessenger.sol - Smart Contract

The `SecureMessenger.sol` smart contract defines a secure messaging system. Here are its key features:

- Participants are defined during contract deployment.
- Messages are stored in an encrypted form on the blockchain.
- Messages are encrypted using AES-256-GCM encryption.
- Only the participants can send and read messages.

You can find the full Solidity code in the `SecureMessenger.sol` file.

### Encryption and Decryption

The encryption and decryption process is handled in the `SecureTool` class using the Elliptic Curve Cryptography (ECC) and AES-256-GCM encryption algorithm. Here are the steps involved:

1. Participants generate an ECC key pair from a seed phrase.
2. When sending a message, the sender encrypts the message using AES-256-GCM with a shared secret derived from ECC key pairs.
3. The encrypted message is then stored on the blockchain.
4. The recipient can decrypt the message using the same shared secret.

You can find the encryption and decryption methods in the `SecureTool` class.

### About

- This example is meant for educational purposes and may not cover all aspects of a production-ready messaging system.
- Care should be taken to ensure the security and privacy of participants' private keys and data.

Feel free to explore, modify, and expand on this example to build more sophisticated secure communication systems on the blockchain.

### How to Use

```shell
yarn install

yarn deploy

yarn test
