const crypto = require('crypto');

const alice = crypto.createECDH('secp256k1');
alice.generateKeys();

const bob = crypto.createECDH('secp256k1');
bob.generateKeys();

const alicePublicKeyBase64 = alice.getPublicKey().toString('base64');
const bobPublicKeyBase64 = bob.getPublicKey().toString('base64');

const aliceSharedKey = alice.computeSecret(bobPublicKeyBase64, 'base64', 'hex');
const bobSharedKey = bob.computeSecret(alicePublicKeyBase64, 'base64', 'hex');

console.log(aliceSharedKey === bobSharedKey);
console.log('Alice shared Key: ', aliceSharedKey);
console.log('Bob shared Key: ', bobSharedKey);

const MESSAGE = 'this is some random message...';

const IV = crypto.randomBytes(16);
const cipher = crypto.createCipheriv(
  'aes-256-gcm',
  Buffer.from(aliceSharedKey, 'hex'),
  IV
);

let encrypted = cipher.update(MESSAGE, 'utf8', 'hex');
encrypted += cipher.final('hex');

const auth_tag = cipher.getAuthTag().toString('hex');

console.table({
  IV: IV.toString('hex'),
  encrypted: encrypted,
  auth_tag: auth_tag
});

const payload = IV.toString('hex') + encrypted + auth_tag;

const payload64 = Buffer.from(payload, 'hex').toString('base64');
console.log(payload64);

//Bob will do from here
const bob_payload = Buffer.from(payload64, 'base64').toString('hex');

const bob_iv = bob_payload.substr(0, 32);
const bob_encrypted = bob_payload.substr(32, bob_payload.length - 32 - 32);
const bob_auth_tag = bob_payload.substr(bob_payload.length - 32, 32);

console.table({ bob_iv, bob_encrypted, bob_auth_tag });

try {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(bobSharedKey, 'hex'),
    Buffer.from(bob_iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(bob_auth_tag, 'hex'));

  let decrypted = decipher.update(bob_encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  console.table({ DecyptedMessage: decrypted });
} catch (error) {
  console.log(error.message);
}
