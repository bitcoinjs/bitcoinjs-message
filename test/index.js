var test = require('tape').test
var bitcoin = require('bitcoinjs-lib')
var BigInteger = require('bigi')
var message = require('../')

var fixtures = require('./fixtures.json')

function getMessagePrefix (networkName) {
  return fixtures.networks[networkName]
}

fixtures.valid.magicHash.forEach(function (f) {
  test('produces the magicHash for "' + f.message + '" (' + f.network + ')', function (t) {
    var actual = message.magicHash(f.message, getMessagePrefix(f.network))
    t.same(actual.toString('hex'), f.magicHash)
    t.end()
  })
})

fixtures.valid.sign.forEach(function (f) {
  test('sign: ' + f.description, function (t) {
    var pk = new bitcoin.ECPair(new BigInteger(f.d)).d.toBuffer(32)
    var signature = message.sign(f.message, pk, false, getMessagePrefix(f.network))
    t.same(signature.toString('base64'), f.signature)

    if (f.compressed) {
      signature = message.sign(f.message, pk, true, getMessagePrefix(f.network))
      t.same(signature.toString('base64'), f.compressed.signature)
    }

    t.end()
  })
})

fixtures.valid.verify.forEach(function (f) {
  test('verifies a valid signature for "' + f.message + '" (' + f.network + ')', function (t) {
    t.true(message.verify(f.message, f.address, f.signature, getMessagePrefix(f.network)))

    if (f.network === 'bitcoin') {
      // defaults to bitcoin network
      t.true(message.verify(f.message, f.address, f.signature))
    }

    if (f.compressed) {
      t.true(message.verify(f.message, f.compressed.address, f.compressed.signature, getMessagePrefix(f.network)))
    }

    t.end()
  })
})

fixtures.invalid.signature.forEach(function (f) {
  test('decode signature: throws on ' + f.hex, function (t) {
    t.throws(function () {
      message.verify(null, null, Buffer.from(f.hex, 'hex'), null)
    }, new RegExp('^Error: ' + f.exception + '$'))
    t.end()
  })
})

fixtures.invalid.verify.forEach(function (f) {
  test(f.description, function (t) {
    t.false(message.verify(f.message, f.address, f.signature, getMessagePrefix('bitcoin')))
    t.end()
  })
})

fixtures.randomSig.forEach(function (f) {
  test(f.description, function (t) {
    var keyPair = bitcoin.ECPair.fromWIF(f.wif)
    var privateKey = keyPair.d.toBuffer(32)
    var address = keyPair.getAddress()
    f.signatures.forEach(function (s) {
      var signature = message.sign(f.message, privateKey, keyPair.compressed, undefined, {data: Buffer.from(s.sigData, 'base64')})
      t.true(message.verify(f.message, address, signature))
      signature = message.sign(f.message, privateKey, keyPair.compressed, {data: Buffer.from(s.sigData, 'base64')})
      t.true(message.verify(f.message, address, signature))
    })
    t.end()
  })
})
