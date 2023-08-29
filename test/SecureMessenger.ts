import { expect } from 'chai';

import { getBytes, zeroPadValue } from 'ethers';
import { ethers } from 'hardhat';
import { SecureTool } from '../scripts/secure-messenger';
import { SecureMessenger } from '../typechain-types';
import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';


describe('SecureMessenger', () => {
  let secureMessenger: SecureMessenger;
  let participant1: HardhatEthersSigner;
  let participant2: HardhatEthersSigner;
  let guest: HardhatEthersSigner

  beforeEach(async () => {
    const SecureMessengerFactory = await ethers.getContractFactory('SecureMessenger');
    [participant1, participant2, guest ] = await ethers.getSigners();

    secureMessenger = (await SecureMessengerFactory.deploy(participant1.address, participant2.address)) as SecureMessenger;
    await secureMessenger.waitForDeployment();
  });

  it('should send and receive encrypted messages', async () => {
    const data = SecureTool.encrypt("Hello world")
    const encryptedMessage = SecureTool.encrypt("Hello world")
    
    await secureMessenger.connect(participant1).sendEncryptedMessage(encryptedMessage);

    const receivedMessages = await secureMessenger.connect(participant1).getEncryptedMessages();
    expect(receivedMessages).to.have.lengthOf(1);
    expect(receivedMessages[0].sender).to.equal(participant1.address);
    expect(receivedMessages[0].encryptedMessage).to.equal(`0x${encryptedMessage.toString("hex")}`);
  });

  it('should not allow unauthorized participants to interact', async () => {
    const unauthorized = null

    const unauthorizedEncryptedMessage = SecureTool.encrypt("Hello world")
    await expect(secureMessenger.connect(guest).sendEncryptedMessage(unauthorizedEncryptedMessage)).to.be.revertedWith('Unauthorized');
  });
});
