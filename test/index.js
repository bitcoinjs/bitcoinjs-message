/* global describe, it */

var assert = require('assert')
var bitcoin = require('bitcoinjs-lib')
var message = require('../')

var BigInteger = require('bigi')
var fixtures = require('./fixtures.json')
var PREFIXES = {
  'bitcoin': '\x18Bitcoin Signed Message:\n',
  'litecoin': '\x19Litecoin Signed Message:\n',
  'dogecoin': '\x19Dogecoin Signed Message:\n'
}

describe('message', function () {
  function fromRaw (signature) {
    return {
      r: new BigInteger(signature.r),
      s: new BigInteger(signature.s)
    }
  }

  function toRaw (signature) {
    return {
      r: signature.r.toString(),
      s: signature.s.toString()
    }
  }

  describe('compactSignature', function () {
    fixtures.valid.compactSignature.forEach(function (f) {
      it('exports ' + f.hex + ' correctly', function () {
        var signature = fromRaw(f.signature)
        var buffer = message.compactSignature(signature, f.i, f.compressed)

        assert.strictEqual(buffer.toString('hex'), f.hex)
      })
    })
  })

  describe('parseCompactSignature', function () {
    fixtures.valid.compactSignature.forEach(function (f) {
      it('imports ' + f.hex + ' correctly', function () {
        var buffer = new Buffer(f.hex, 'hex')
        var parsed = message.parseCompactSignature(buffer)

        assert.strictEqual(parsed.compressed, f.compressed)
        assert.strictEqual(parsed.i, f.i)
        assert.deepEqual(toRaw(parsed.signature), f.signature)
      })
    })

    fixtures.invalid.compactSignature.forEach(function (f) {
      it('throws on ' + f.hex, function () {
        var buffer = new Buffer(f.hex, 'hex')

        assert.throws(function () {
          message.parseCompactSignature(buffer)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('magicHash', function () {
    fixtures.valid.magicHash.forEach(function (f) {
      it('produces the magicHash for "' + f.message + '" (' + f.network + ')', function () {
        var actual = message.magicHash(f.message, PREFIXES[f.network])

        assert.strictEqual(actual.toString('hex'), f.magicHash)
      })
    })
  })

  describe('verify', function () {
    fixtures.valid.verify.forEach(function (f) {
      it('verifies a valid signature for "' + f.message + '" (' + f.network + ')', function () {
        assert(message.verify(f.address, f.signature, f.message, PREFIXES[f.network]))

        if (f.compressed) {
          assert(message.verify(f.compressed.address, f.compressed.signature, f.message, PREFIXES[f.network]))
        }
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it(f.description, function () {
        assert(!message.verify(f.address, f.signature, f.message))
      })
    })
  })

  describe('signing', function () {
    fixtures.valid.signing.forEach(function (f) {
      it(f.description, function () {
        var keyPair = new bitcoin.ECPair(new BigInteger(f.d), null, {
          compressed: false
        })
        var signature = message.sign(keyPair, f.message, PREFIXES[f.network])
        assert.strictEqual(signature.toString('base64'), f.signature)

        if (f.compressed) {
          var compressedPrivKey = new bitcoin.ECPair(new BigInteger(f.d))
          var compressedSignature = message.sign(compressedPrivKey, f.message)

          assert.strictEqual(compressedSignature.toString('base64'), f.compressed.signature)
        }
      })
    })
  })
})
