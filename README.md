# bitcoinjs-message

[![NPM](http://img.shields.io/npm/v/bitcoin-message.svg)](https://www.npmjs.org/package/bitcoin-message)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)


## Example

``` javascript
var bitcoin = require('bitcoinjs-lib')
var bitcoinMessage = require('bitcoinjs-message')
```

Sign a Bitcoin message

``` javascript
var keyPair = bitcoin.ECPair.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')
var message = 'This is an example of a signed message.'

var signature = bitcoinMessage.sign(keyPair, message)
console.log(signature.toString('base64'))
// => 'G9L5yLFjti0QTHhPyFrZCT1V/MMnBtXKmoiKDZ78NDBjERki6ZTQZdSMCtkgoNmp17By9ItJr8o7ChX0XxY91nk='
```


Verify a Bitcoin message

``` javascript
var address = '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN'
var signature = 'HJLQlDWLyb1Ef8bQKEISzFbDAKctIlaqOpGbrk3YVtRsjmC61lpE5ErkPRUFtDKtx98vHFGUWlFhsh3DiW6N0rE'
var message = 'This is an example of a signed message.'

console.log(bitcoinMessage.verify(address, signature, message))
// => true
```

## LICENSE [MIT](LICENSE)
