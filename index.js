var bs58check = require('bs58check')
var bitcoin = require('bitcoinjs-lib')
var ecdsa = require('./ecdsa')
var compactSignature = require('./signature')

function magicHash (message, network) {
  network = network || bitcoin.networks.bitcoin

  var prefix = network.messagePrefix
  var messageVISize = bitcoin.bufferutils.varIntSize(message.length)
  var buffer = new Buffer(prefix.length + messageVISize + message.length)

  buffer.write(prefix, 0)
  bitcoin.bufferutils.writeVarInt(buffer, message.length, prefix.length)
  buffer.write(message, prefix.length + messageVISize)

  return bitcoin.crypto.hash256(buffer)
}

function sign (keyPair, message, network) {
  var hash = magicHash(message, network)
  var signature = keyPair.sign(hash)
  var i = ecdsa.calcPubKeyRecoveryParam(hash, signature, keyPair.Q)

  return compactSignature.encode(signature, i, keyPair.compressed)
}

function verify (address, signature, message, network) {
  if (!Buffer.isBuffer(signature)) {
    signature = new Buffer(signature, 'base64')
  }

  var parsed = compactSignature.decode(signature)
  var hash = magicHash(message, network)
  var Q = ecdsa.recoverPubKey(hash, parsed.signature, parsed.i)
  var Qb = Q.getEncoded(parsed.compressed)

  var actual = bitcoin.crypto.hash160(Qb)
  var expected = bs58check.decode(address).slice(1)

  return bitcoin.bufferutils.equal(actual, expected)
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  verify: verify
}
