# crypto-containers
JavaScript library to encrypt plain text or raw data into a crypto container and decrypt crypto container with randomly generated an encryption key. Encryption and decryption derive by reassembling encryption key which was split into shares by [Shamir's Secret Sharing algorithm](http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing).

## What you can do with it?
The crypto-containers library allows you to encrypt and decrypt any information. We use this library in Key2Lyf production as a secure way to split access and storing any sensitive information.

## Usage
To use it in the browser, include cryptoContainers.js or cryptoContainers.min.js in your HTML. You can find them in the `lib/ ` folder.

  ` <script src="cryptoContainers.min.js"></script> `
  

## API
* cryptoContainers.generateKey()
* cryptoContainers.getEncryptionKey()
* cryptoContainers.encryptContainer()
* cryptoContainers.decryptContainer()
* cryptoContainers.encryptionKeyIsValid()
* cryptoContainers.userShareIsValid()
* cryptoContainers.hashData()

See all `Variables description` below.

#### cryptoContainers.generateKey( salt )
Generate a random encryption key with default length 24 symbols. Salt is an optional argument. If salt wasn't provided random salt value will be generated.
The output of `cryptoContainers.generateKey()` is an Object like this:
 
` {encryptionKeyHash: "6a8e835ed6412428e3bf1347a85d3f37c65777d36fe2ce59f7b082ef85fbe29a", 
userHashedShare: "0fc46dc212e5b7d6be1741abf8e2503ca4e712a9db3b51cb29b4ce129db6510c", 
k2lShare: "801bfd2ba3b2b38b56e0211c33a9da6d23ffcf338d18868f8b…97425aa1e8212e0d58ec82ac15c59103614520c0f72b2af2b", 
userShare: "80260b9ca76f37024dca122ce747b51137e4afb29bf5dd04e7…de8024966198bddee012b54d7b817203328fd18bbe423430a",
salt: "e6d2b914"}`

Each item in the object is a String.


#### cryptoContainers.getEncryptionKey( k2lShare, userShare, action )
Reconstructs the encryption key from `k2lShare` and `userShare` shares. The output is an encryption key, a String.


#### cryptoContainers.encryptContainer( rawData, encryptionKey, action )
Returns an encrypted by the encryption key data.


#### cryptoContainers.decryptContainer(encryptedData, encryptionKey, action)
Uses the encryption key to decrypt encryptedData. Returns rawData.


#### cryptoContainers.encryptionKeyIsValid( encryptionKeyHash, encryptionKey, salt )
Hashes the encryptionKey and compares gotten hash with encryptionKeyHash. Returns true or false.


#### cryptoContainers.userShareIsValid( userShare, userHashedShare, salt )
Hashes the userShare and compares gotten hash with userHashedShare. Returns true or false.


#### cryptoContainers.hashData( data, salt )
Returns hashed data.

## Variables description

Each variable used in the library is described below:
* `encryptionKey`: The key used for encryption and decryption data. Example, "46c75c8b7e68ea07ef43c1ca".
* `encryptionKeyHash`: The hash of the generated encryption key. Example, "40a26f14d7e32968e5a61f530c88b6af1c3db63e0edbd235ff6bf29f33b9795a".
* `k2lShare`: The share which goes to the key2lyf server. The length of this string depends on the length of the encryption key. Example, "801bfd2ba3b2b38b56e0211c33a9da6d23ffcf338d18868f8b1597425aa1e8212e0d58ec82ac15c59103614520c0f72b2af2b".
* `userShare`: The share which goes to the user. The length of this string depends on the length of the encryption key. Example, "80260b9ca76f37024dca122ce747b51137e4afb29bf5dd04e7f1de8024966198bddee012b54d7b817203328fd18bbe423430a".
* `userHashedShare`: The hash  of the userShare. Example, "0fc46dc212e5b7d6be1741abf8e2503ca4e712a9db3b51cb29b4ce129db6510c"
* `action`: js function, is always optional.
* `rawData`: Raw data or plain text for encryption. Example, "Any your sensitive data here. For example, Login: iam.key2lyf, password: dRfi238Pe".
* `encryptedData`: Encrypted data String. Example, "U2FsdGVkX1+WrNdyOv9qqd2rB2tR47au5otU/5Y7tjIQJaurIJN/FK5LJr2R0gmZFbLKxfyc7g6zePNAV+M6C35W1H4caZayE9GlLeHbb7nX5tl9k+KIahrsZPTB+aC3sHoj1oicQTr8x63C7OFEYg=="
* `salt`: Is random generated 8 symbols length String.

## Contributing

Please send pull requests for bug fixes, code optimization, and ideas for improvement. 


## License

Code released under [the MIT license](https://github.com/Key2Lyf/crypto-containers/blob/master/LICENSE).

Copyright 2018 Key2Lyf
