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
    var signature = message.sign(f.message, getMessagePrefix(f.network), pk, false)
    t.same(signature.toString('base64'), f.signature)

    if (f.compressed) {
      signature = message.sign(f.message, getMessagePrefix(f.network), pk, true)
      t.same(signature.toString('base64'), f.compressed.signature)
    }

    t.end()
  })
})

fixtures.valid.verify.forEach(function (f) {
  test('verifies a valid signature for "' + f.message + '" (' + f.network + ')', function (t) {
    t.true(message.verify(f.message, getMessagePrefix(f.network), f.address, f.signature))

    if (f.compressed) {
      t.true(message.verify(f.message, getMessagePrefix(f.network), f.compressed.address, f.compressed.signature))
    }

    t.end()
  })
})

fixtures.invalid.signature.forEach(function (f) {
  test('decode signature: throws on ' + f.hex, function (t) {
    t.throws(function () {
      message.verify(null, null, null, Buffer.from(f.hex, 'hex'))
    }, new RegExp('^Error: ' + f.exception + '$'))
    t.end()
  })
})

fixtures.invalid.verify.forEach(function (f) {
  test(f.description, function (t) {
    t.false(message.verify(f.message, getMessagePrefix('bitcoin'), f.address, f.signature))
    t.end()
  })
})
