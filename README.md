# bitcoinjs-message
[![NPM Package](https://img.shields.io/npm/v/bitcoinjs-message.svg?style=flat-square)](https://www.npmjs.org/package/bitcoinjs-message)
[![Build Status](https://img.shields.io/travis/bitcoinjs/bitcoinjs-message.svg?branch=master&style=flat-square)](https://travis-ci.org/bitcoinjs/bitcoinjs-message)
[![Dependency status](https://img.shields.io/david/bitcoinjs/bitcoinjs-message.svg?style=flat-square)](https://david-dm.org/bitcoinjs/bitcoinjs-message#info=dependencies)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

## Examples

``` javascript
var bitcoin = require('bitcoinjs-lib') // v3.x.x
var bitcoinMessage = require('bitcoinjs-message')
```

> sign(message, privateKey, compressed[, network.messagePrefix, segwitType])

Sign a Bitcoin message
``` javascript
var keyPair = bitcoin.ECPair.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')
var privateKey = keyPair.privateKey
var message = 'This is an example of a signed message.'

var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed)
console.log(signature.toString('base64'))
// => 'G9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

Sign a Bitcoin message (with segwit addresses)
``` javascript
// P2SH(P2WPKH) address 'p2sh(p2wpkh)'
var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed, null, 'p2sh(p2wpkh)')
console.log(signature.toString('base64'))
// => 'I9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='

// P2WPKH address 'p2wpkh'
var signature = bitcoinMessage.sign(message, privateKey, keyPair.compressed, null, 'p2wpkh')
console.log(signature.toString('base64'))
// => 'J9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```

> verify(message, address, signature[, network.messagePrefix])

Verify a Bitcoin message
``` javascript
var address = '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN'

console.log(bitcoinMessage.verify(message, address, signature))
// => true
```

## LICENSE [MIT](LICENSE)
