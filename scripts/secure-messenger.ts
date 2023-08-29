import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { ec as EC, curve } from 'elliptic';

const secp256k1 = new EC('secp256k1');

function encryptMessage(message: string, selfPrivatePair: EC.KeyPair, participantPublicKey: curve.base.BasePoint) {
    const sharedSecret = selfPrivatePair.derive(participantPublicKey);
    const sharedSecretBuffer = Buffer.from(sharedSecret.toArray());
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecretBuffer, iv, { authTagLength: 16 });
    const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted])
}

function decryptMessage(encryptedMessageHex: string, selfPrivatePair: EC.KeyPair, participantPublicKey: curve.base.BasePoint ): string {
    const sharedSecret = selfPrivatePair.derive(participantPublicKey);
    const sharedSecretBuffer = Buffer.from(sharedSecret.toArray());
    const encryptedMessage = Buffer.from(encryptedMessageHex, 'hex');
    const iv = encryptedMessage.slice(0, 12);
    const authTag = encryptedMessage.slice(12, 28);
    const ciphertext = encryptedMessage.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecretBuffer, iv, { authTagLength: 16 });
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf-8');
}


export class SecureTool {
    public keyPair: EC.KeyPair

    constructor(seed: string){
        this.keyPair = secp256k1.keyFromPrivate(bcrypt.hashSync(seed, 10));
    }

    public encrypt(message: string, participant: SecureTool){
        return encryptMessage(message, this.keyPair, participant.keyPair.getPublic())
    }

    // substring removes "0x" from value for decrypt
    public decrypt(encryptedMessage: string, participant: SecureTool){
        return decryptMessage(encryptedMessage.substring(2), this.keyPair, participant.keyPair.getPublic())
    }

    static bufferToEthersHex(encryptedMessage: Buffer){
        return `0x${encryptedMessage.toString("hex")}`
    }
}







