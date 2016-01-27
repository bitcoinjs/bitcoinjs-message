/* global describe, it */

var assert = require('assert')
var bitcoin = require('bitcoinjs-lib')
var BigInteger = require('bigi')
var message = require('../')

var fixtures = require('./fixtures.json')
var NETWORKS = bitcoin.networks

describe('message', function () {
  describe('_encodeSignature', function () {
    fixtures.valid.signature.forEach(function (f) {
      it('exports ' + f.hex + ' correctly', function () {
        var signature = new Buffer(f.signature, 'hex')
        var buffer = message._encodeSignature(signature, f.recovery, f.compressed)

        assert.strictEqual(buffer.toString('hex'), f.hex)
      })
    })
  })

  describe('_decodeSignature', function () {
    fixtures.valid.signature.forEach(function (f) {
      it('imports ' + f.hex + ' correctly', function () {
        var buffer = new Buffer(f.hex, 'hex')
        var decode = message._decodeSignature(buffer)

        assert.deepEqual(decode, {
          signature: new Buffer(f.signature, 'hex'),
          recovery: f.recovery,
          compressed: f.compressed
        })
      })
    })

    fixtures.invalid.signature.forEach(function (f) {
      it('throws on ' + f.hex, function () {
        var buffer = new Buffer(f.hex, 'hex')

        assert.throws(function () {
          message._decodeSignature(buffer)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('magicHash', function () {
    fixtures.valid.magicHash.forEach(function (f) {
      it('produces the magicHash for "' + f.message + '" (' + f.network + ')', function () {
        var actual = message.magicHash(f.message, NETWORKS[f.network])

        assert.strictEqual(actual.toString('hex'), f.magicHash)
      })
    })
  })

  describe('sign', function () {
    fixtures.valid.sign.forEach(function (f) {
      it(f.description, function () {
        var keyPair = new bitcoin.ECPair(new BigInteger(f.d), null, {
          compressed: false
        })
        var signature = message.sign(keyPair, f.message, NETWORKS[f.network])
        assert.strictEqual(signature.toString('base64'), f.signature)

        if (f.compressed) {
          var compressedPrivKey = new bitcoin.ECPair(new BigInteger(f.d))
          var compressedSignature = message.sign(compressedPrivKey, f.message)

          assert.strictEqual(compressedSignature.toString('base64'), f.compressed.signature)
        }
      })
    })
  })

  describe('verify', function () {
    fixtures.valid.verify.forEach(function (f) {
      it('verifies a valid signature for "' + f.message + '" (' + f.network + ')', function () {
        assert(message.verify(f.address, f.signature, f.message, NETWORKS[f.network]))

        if (f.compressed) {
          assert(message.verify(f.compressed.address, f.compressed.signature, f.message, NETWORKS[f.network]))
        }
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it(f.description, function () {
        assert(!message.verify(f.address, f.signature, f.message))
      })
    })
  })
})
