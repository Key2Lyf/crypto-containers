const CryptoJS = require('crypto-js');
const secrets = require('secrets.js');

function dec2hex(dec) {
  // Generate random string/characters
  // dec2hex :: Integer -> String
  return ('0' + dec.toString(16)).substr(-2);
}

function generateId(len) {
  // generateId :: Integer -> String
  const arr = new Uint8Array((len || 40) / 2);

  window.crypto.getRandomValues(arr);
  return Array.from(arr, dec2hex).join('');
}

function generateKey() {

  const encryptionKey = generateId(24);

  const encryptionKeyHex = secrets.str2hex(encryptionKey); // => hex string

  // split into 2 shares with a threshold of 2
  const shares = secrets.share(encryptionKeyHex, 2, 2);

  const k2lShare = shares[0];
  const userShare = shares[1];
  const salt = generateId(8);

  // hashing of the encryption key
  const encryptionKeyHash = CryptoJS.HmacSHA256(encryptionKey, salt);
  const userHashedShare = CryptoJS.HmacSHA256(userShare, salt);

  return {
    encryptionKeyHash: encryptionKeyHash.toString(CryptoJS.enc.Hex),
    userHashedShare: userHashedShare.toString(CryptoJS.enc.Hex),
    k2lShare: k2lShare,
    userShare: userShare,
    salt: salt
  };
}

function userShareIsValid(userShare, userHashedShare, salt) {
  // hashing of the shares
  const userShareHash = CryptoJS.HmacSHA256(userShare, salt);

  return (userShareHash.toString(CryptoJS.enc.Hex) === userHashedShare);
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
  const generatedEncryptionKeyHash = CryptoJS.HmacSHA256(encryptionKey, salt);

  return (generatedEncryptionKeyHash.toString(CryptoJS.enc.Hex) === encryptionKeyHash);
}

export {
  generateKey,
  userShareIsValid,
  getEncryptionKey,
  encryptContainer,
  decryptContainer,
  encryptionKeyIsValid
};
