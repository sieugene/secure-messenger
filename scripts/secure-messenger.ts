import { ec as EC, curve } from 'elliptic';
import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';

const secp256k1 = new EC('secp256k1');


// Seed phrase
const participant1SeedPhrase = 'Participant1SeedPhrase';
const participant2SeedPhrase = 'Participant2SeedPhrase';

// Seed in Keys
const participant1PrivateKey = secp256k1.keyFromPrivate(bcrypt.hashSync(participant1SeedPhrase, 10));
const participant1PublicKey = participant1PrivateKey.getPublic();
const participant2PrivateKey = secp256k1.keyFromPrivate(bcrypt.hashSync(participant2SeedPhrase, 10));
const participant2PublicKey = participant2PrivateKey.getPublic();


function encryptMessage(message: string, publicKey: curve.base.BasePoint): string {
    const sharedSecret = participant1PrivateKey.derive(publicKey);
    const sharedSecretBuffer = Buffer.from(sharedSecret.toArray()); // Преобразование в буфер
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecretBuffer, iv, { authTagLength: 16 });
    const encrypted = Buffer.concat([cipher.update(message, 'utf-8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString('hex');
}

function decryptMessage(encryptedMessageHex: string, privateKey: EC.KeyPair): string {
    const sharedSecret = privateKey.derive(participant2PublicKey);
    const sharedSecretBuffer = Buffer.from(sharedSecret.toArray()); // Преобразование в буфер
    const encryptedMessage = Buffer.from(encryptedMessageHex, 'hex');
    const iv = encryptedMessage.slice(0, 12);
    const authTag = encryptedMessage.slice(12, 28);
    const ciphertext = encryptedMessage.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecretBuffer, iv, { authTagLength: 16 });
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf-8');
}

const originalMessage = 'Hello, world!';
const encryptedMessage = encryptMessage(originalMessage, participant2PublicKey);
console.log('Зашифрованное сообщение:', encryptedMessage);
const decryptedMessage = decryptMessage(encryptedMessage, participant1PrivateKey);
console.log('Расшифрованное сообщение:', decryptedMessage);


 class Tool {
    encrypt(message: string){
        return encryptMessage(message, participant2PublicKey);
    }
    decrypt(encryptedMessage:string){
        return decryptMessage(encryptedMessage, participant1PrivateKey);
    }
}

export const SecureTool = new Tool()