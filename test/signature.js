/* global describe, it */

var assert = require('assert')
var msignature = require('../signature')

var BigInteger = require('bigi')
var fixtures = require('./fixtures-signature')

describe('compactSignature', function () {
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

  describe('decode', function () {
    fixtures.valid.forEach(function (f) {
      it('imports ' + f.hex + ' correctly', function () {
        var buffer = new Buffer(f.hex, 'hex')
        var decode = msignature.decode(buffer)

        assert.strictEqual(decode.compressed, f.compressed)
        assert.strictEqual(decode.i, f.i)
        assert.deepEqual(toRaw(decode.signature), f.signature)
      })
    })

    fixtures.invalid.forEach(function (f) {
      it('throws on ' + f.hex, function () {
        var buffer = new Buffer(f.hex, 'hex')

        assert.throws(function () {
          msignature.decode(buffer)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('encode', function () {
    fixtures.valid.forEach(function (f) {
      it('exports ' + f.hex + ' correctly', function () {
        var signature = fromRaw(f.signature)
        var buffer = msignature.encode(signature, f.i, f.compressed)

        assert.strictEqual(buffer.toString('hex'), f.hex)
      })
    })
  })
})
