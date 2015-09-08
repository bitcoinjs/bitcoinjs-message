var bs58check = require('bs58check')
var bitcoin = require('bitcoinjs-lib')
var ecdsa = require('./ecdsa')

var BigInteger = require('bigi')

function compactSignature (signature, i, compressed) {
  if (compressed) {
    i += 4
  }

  i += 27

  var buffer = new Buffer(65)
  buffer.writeUInt8(i, 0)

  signature.r.toBuffer(32).copy(buffer, 1)
  signature.s.toBuffer(32).copy(buffer, 33)

  return buffer
}

function parseCompactSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  var flagByte = buffer.readUInt8(0) - 27
  if (flagByte !== (flagByte & 7)) throw new Error('Invalid signature parameter')

  var compressed = !!(flagByte & 4)
  var recoveryParam = flagByte & 3

  var r = BigInteger.fromBuffer(buffer.slice(1, 33))
  var s = BigInteger.fromBuffer(buffer.slice(33))

  return {
    compressed: compressed,
    i: recoveryParam,
    signature: { r: r, s: s }
  }
}

function magicHash (message, prefix) {
  prefix = prefix || '\x18Bitcoin Signed Message:\n'

  var messageVISize = bitcoin.bufferutils.varIntSize(message.length)
  var buffer = new Buffer(prefix.length + messageVISize + message.length)

  buffer.write(prefix, 0)
  bitcoin.bufferutils.writeVarInt(buffer, message.length, prefix.length)
  buffer.write(message, prefix.length + messageVISize)

  return bitcoin.crypto.hash256(buffer)
}

function sign (keyPair, message, messagePrefix) {
  var hash = magicHash(message, messagePrefix)
  var signature = keyPair.sign(hash)
  var e = BigInteger.fromBuffer(hash)
  var i = ecdsa.calcPubKeyRecoveryParam(e, signature, keyPair.Q)

  return compactSignature(signature, i, keyPair.compressed)
}

function verify (address, signature, message, messagePrefix) {
  if (!Buffer.isBuffer(signature)) {
    signature = new Buffer(signature, 'base64')
  }

  var hash = magicHash(message, messagePrefix)
  var parsed = parseCompactSignature(signature)
  var e = BigInteger.fromBuffer(hash)
  var Q = ecdsa.recoverPubKey(e, parsed.signature, parsed.i)
  var Qb = Q.getEncoded(parsed.compressed)

  var actual = bitcoin.crypto.hash160(Qb)
  var expected = bs58check.decode(address).slice(1)

  return bitcoin.bufferutils.equal(actual, expected)
}

module.exports = {
  magicHash: magicHash,

  compactSignature: compactSignature,
  parseCompactSignature: parseCompactSignature,
  sign: sign,
  verify: verify
}
