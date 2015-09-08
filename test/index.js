/* global describe, it */

var assert = require('assert')
var bitcoin = require('bitcoinjs-lib')
var message = require('../')

var BigInteger = require('bigi')
var fixtures = require('./fixtures.json')
var NETWORKS = bitcoin.networks

describe('message', function () {
  describe('magicHash', function () {
    fixtures.valid.magicHash.forEach(function (f) {
      it('produces the magicHash for "' + f.message + '" (' + f.network + ')', function () {
        var actual = message.magicHash(f.message, NETWORKS[f.network])

        assert.strictEqual(actual.toString('hex'), f.magicHash)
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

  describe('signing', function () {
    fixtures.valid.signing.forEach(function (f) {
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
})
