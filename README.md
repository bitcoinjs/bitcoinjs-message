# dogecoin-message-signer
[![NPM Package](https://img.shields.io/npm/v/bitcoinjs-message.svg?style=flat-square)](https://www.npmjs.org/package/bitcoinjs-message)
[![Build Status](https://img.shields.io/travis/bitcoinjs/bitcoinjs-message.svg?branch=master&style=flat-square)](https://travis-ci.org/bitcoinjs/bitcoinjs-message)
[![Dependency status](https://img.shields.io/david/bitcoinjs/bitcoinjs-message.svg?style=flat-square)](https://david-dm.org/bitcoinjs/bitcoinjs-message#info=dependencies)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

## Examples

``` javascript
var cryptocoin = require('bitcoinjs-lib') // v3.x.x
var cryptocoinMessage = require('bitcoinjs-message')
```

> sign(message, privateKey, compressed[, network.messagePrefix])

Sign a Dogecoin message
``` javascript

var dogecoinNetwork =   {
    messagePrefix: '\x19Dogecoin Signed Message:\n',
    bip32: {
      public: 0x02facafd,
      private: 0x02fac398
    },
    pubKeyHash: 0x1e,
    scriptHash: 0x16,
    wif: 0x9e
  }

var keyPair = cryptocoin.ECPair.fromWIF('6Kq3vjVfdF5TwFBZ9r1yZAPYtKSxotvm45EXjxkwR5p3aNb4DKX', dogecoinNetwork);
var privateKey = keyPair.__d;
var message = 'This is an example of a dogecoin signed message.';

var signature = cryptocoinMessage.sign(message, privateKey, keyPair.compressed);
console.log(signature.toString('base64'));
// => HCo9HyAmfVmLnEfTvsB+kwr+j9LbWV1lOwPKi2OpOaOBOxkOnUTXjx5o2cURRPe88vYHa4AKyVjJLR9zoEB90Rs=
```

> verify(message, address, signature[, network.messagePrefix]);

Verify a Dogecoin message
``` javascript
var address = 'DTAbymNwBLCHiCcwD2oToaKX6ZVgUQ2b2g';

console.log(cryptocoinMessage.verify(message, address, signature));
// => true
```

## LICENSE [MIT](LICENSE)
