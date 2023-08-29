import { expect } from 'chai';

import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import { ethers } from 'hardhat';
import { SecureTool } from '../scripts/secure-messenger';
import { SecureMessenger } from '../typechain-types';


describe('SecureMessenger', () => {
  let secureMessenger: SecureMessenger;
  let participant1: HardhatEthersSigner;
  let participant2: HardhatEthersSigner;
  let guest: HardhatEthersSigner
  let participant1Tool: SecureTool
  let participant2Tool: SecureTool
  let originalMessage = "Hello world"

  beforeEach(async () => {
    const SecureMessengerFactory = await ethers.getContractFactory('SecureMessenger');
    [participant1, participant2, guest ] = await ethers.getSigners();

    participant1Tool = new SecureTool("participant1Seed")
    participant2Tool = new SecureTool("participant2Seed")

    secureMessenger = (await SecureMessengerFactory.deploy(participant1.address, participant2.address)) as SecureMessenger;
    await secureMessenger.waitForDeployment();
  });

  it('should bee encrypt and decrypt', async () => {
    const encryptedMessage = participant1Tool.encrypt(originalMessage, participant2Tool)
    const messageFromEther = SecureTool.bufferToEthersHex(encryptedMessage)
    const decryptedMessage = participant2Tool.decrypt(messageFromEther, participant1Tool)
    console.log('encryptedMessage', encryptedMessage)
    console.log('decryptedMessage', decryptedMessage)

    expect(originalMessage).to.equal(decryptedMessage)
  });

  it('should send and receive encrypted messages', async () => {
    const encryptedMessage = participant1Tool.encrypt(originalMessage, participant2Tool)
    
    await secureMessenger.connect(participant1).sendEncryptedMessage(encryptedMessage);

    const receivedMessages = await secureMessenger.connect(participant1).getEncryptedMessages(participant1.address);
    const firstMessage = receivedMessages[0]
    console.log("participant1 :: receivedMessages",receivedMessages)
    expect(receivedMessages).to.have.lengthOf(1);
    expect(firstMessage.sender).to.equal(participant1.address);
    expect(firstMessage.encryptedMessage).to.equal(SecureTool.bufferToEthersHex(encryptedMessage));
    // participant2

    const receivedMessages2 = await secureMessenger.connect(participant2).getEncryptedMessages(participant1.address);
    const firstMessage2 = receivedMessages2[0].encryptedMessage
    const decryptedMessage = participant2Tool.decrypt(firstMessage2, participant1Tool)
    expect(originalMessage).to.equal(decryptedMessage);

  });



  it('should not allow unauthorized participants to sendEncryptedMessage', async () => {

    const unauthorizedEncryptedMessage = participant1Tool.encrypt(originalMessage, participant2Tool)
    await expect(secureMessenger.connect(guest).sendEncryptedMessage(unauthorizedEncryptedMessage)).to.be.revertedWith('Unauthorized');
  });

  it('should not allow unauthorized participants to getEncryptedMessages', async () => {
    await expect(secureMessenger.connect(guest).getEncryptedMessages(participant1.address)).to.be.revertedWith('Unauthorized');
  });

  
});
