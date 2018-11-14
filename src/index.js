const CryptoJS = require('crypto-js');
const secrets = require('secrets.js');
const crypto = require('crypto');

function dec2hex(dec) {
  // Generate random string/characters
  // dec2hex :: Integer -> String
  return ('0' + dec.toString(16)).substr(-2);
}

function hashData(data, salt) {
  const hashedData = CryptoJS.HmacSHA256(data, salt);

  return hashedData.toString(CryptoJS.enc.Hex);
}

function generateId(len) {
  // generateId :: Integer -> String

  if (typeof window === 'undefined') {
    const buf = crypto.randomBytes(24);

    return buf.toString('hex');

  }
  const arr = new Uint8Array((len || 40) / 2);

  window.crypto.getRandomValues(arr);
  return Array.from(arr, dec2hex).join('');

}

function generateKey(salt) {

  const encryptionKey = generateId(24);

  const encryptionKeyHex = secrets.str2hex(encryptionKey); // => hex string

  // split into 2 shares with a threshold of 2
  const shares = secrets.share(encryptionKeyHex, 2, 2);

  const k2lShare = shares[0];
  const userShare = shares[1];

  if (typeof salt === 'undefined') {
    salt = generateId(8);
  }

  return {
    encryptionKeyHash: hashData(encryptionKey, salt),
    userHashedShare: hashData(userShare, salt),
    k2lShare: k2lShare,
    userShare: userShare,
    salt: salt
  };
}

function userShareIsValid(userShare, userHashedShare, salt) {
  return (hashData(userShare, salt) === userHashedShare);
}

function getEncryptionKey(k2lShare, userShare, action) {
  const encryptionKey = secrets.combine([k2lShare, userShare]);

  if (action) {
    action(secrets.hex2str(encryptionKey));
  }

  // convert back to UTF string and return:
  return secrets.hex2str(encryptionKey);
}

function encryptContainer(rawData, encryptionKey, action) {
  // Encrypt
  const encryptedData = CryptoJS.AES.encrypt(rawData, encryptionKey);

  if (action) {
    action(encryptedData.toString());
  }
  return encryptedData.toString();
}

function decryptContainer(encryptedData, encryptionKey, action) {
  // Decrypt
  const bytes = CryptoJS.AES.decrypt(encryptedData, encryptionKey);

  if (action) {
    action(bytes.toString(CryptoJS.enc.Utf8));
  }

  return bytes.toString(CryptoJS.enc.Utf8);
}

function encryptionKeyIsValid(encryptionKeyHash, encryptionKey, salt) {
  return (hashData(encryptionKey, salt) === encryptionKeyHash);
}

export {
  hashData,
  generateKey,
  userShareIsValid,
  getEncryptionKey,
  encryptContainer,
  decryptContainer,
  encryptionKeyIsValid
};
