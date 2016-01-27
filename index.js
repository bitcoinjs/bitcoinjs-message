var bitcoin = require('bitcoinjs-lib')
var bs58check = require('bs58check')
var secp256k1 = require('secp256k1')

/**
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {boolean} compressed
 * @return {Buffer}
 */
function encodeSignature (signature, recovery, compressed) {
  if (compressed) {
    recovery += 4
  }

  return Buffer.concat([new Buffer([recovery + 27]), signature])
}

/**
 * @param {Buffer} buffer
 * @return {{signature: Buffer, recovery: number, compressed: boolean}}
 */
function decodeSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  var flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 7) throw new Error('Invalid signature parameter')

  return {
    compressed: !!(flagByte & 4),
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

/**
 * @param {string} message
 * @param {Object} [network]
 * @return {Buffer}
 */
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

/**
 * @param {bitcoinjs-lib.ECPair} keyPair
 * @param {string} message
 * @param {Object} [network]
 * @return {Buffer}
 */
function sign (keyPair, message, network) {
  var hash = magicHash(message, network)
  var sigObj = secp256k1.sign(hash, keyPair.d.toBuffer(32))
  return encodeSignature(sigObj.signature, sigObj.recovery, keyPair.compressed)
}

/**
 * @param {string} address
 * @param {(Buffer|string)} signature
 * @param {string} message
 * @param {Object} [network]
 * @return {boolean}
 */
function verify (address, signature, message, network) {
  if (!Buffer.isBuffer(signature)) {
    signature = new Buffer(signature, 'base64')
  }

  var parsed = decodeSignature(signature)
  var hash = magicHash(message, network)
  var publicKey = secp256k1.recover(hash, parsed.signature, parsed.recovery, parsed.compressed)

  var actual = bitcoin.crypto.hash160(publicKey)
  var expected = bs58check.decode(address).slice(1)

  return bitcoin.bufferutils.equal(actual, expected)
}

module.exports = {
  _encodeSignature: encodeSignature,
  _decodeSignature: decodeSignature,
  magicHash: magicHash,
  sign: sign,
  verify: verify
}
