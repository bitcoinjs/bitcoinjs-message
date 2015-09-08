/* global describe, it */

var assert = require('assert')
var bitcoin = require('bitcoinjs-lib')
var compactSignature = require('../signature')
var ecdsa = require('../ecdsa')

var BigInteger = require('bigi')
var curve = ecdsa.__curve

var fixtures = require('./fixtures-ecdsa')

describe('ecdsa', function () {
  function fromRaw (signature) {
    return {
      r: new BigInteger(signature.r, 16),
      s: new BigInteger(signature.s, 16)
    }
  }

  describe('recoverPubKey', function () {
    fixtures.valid.forEach(function (f) {
      it('recovers the pubKey for ' + f.d, function () {
        var d = BigInteger.fromHex(f.d)
        var Q = curve.G.multiply(d)
        var signature = fromRaw(f.signature)
        var hash = bitcoin.crypto.sha256(f.message)
        var Qprime = ecdsa.recoverPubKey(hash, signature, f.i)

        assert(Qprime.equals(Q))
      })
    })

    describe('with i ∈ {0,1,2,3}', function () {
      var hash = new Buffer('feef89995d7575f12d65ccc9d28ccaf7ab224c2e59dad4cc7f6a2b0708d24696', 'hex')

      var signatureBuffer = new Buffer('INcvXVVEFyIfHLbDX+xoxlKFn3Wzj9g0UbhObXdMq+YMKC252o5RHFr0/cKdQe1WsBLUBi4morhgZ77obDJVuV0=', 'base64')
      var signature = compactSignature.decode(signatureBuffer).signature
      var points = [
        '03e3a8c44a8bf712f1fbacee274fb19c0239b1a9e877eff0075ea335f2be8ff380',
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        '03d49e765f0bc27525c51a1b98fb1c99dacd59abe85a203af90f758260550b56c5',
        '027eea09d46ac7fb6aa2e96f9c576677214ffdc238eb167734a9b39d1eb4c3d30d'
      ]

      points.forEach(function (expectedHex, i) {
        it('recovers an expected point for i of ' + i, function () {
          var Qprime = ecdsa.recoverPubKey(hash, signature, i)
          var QprimeHex = Qprime.getEncoded().toString('hex')

          assert.strictEqual(QprimeHex, expectedHex)
        })
      })
    })

    fixtures.invalid.forEach(function (f) {
      it('throws on ' + f.description + ' (' + f.exception + ')', function () {
        var hash = new Buffer(f.e, 'hex')
        var signature = fromRaw(f.signature)

        assert.throws(function () {
          ecdsa.recoverPubKey(hash, signature, f.i)
        }, new RegExp(f.exception))
      })
    })
  })
})
