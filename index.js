var bs58check = require('bs58check')
var bech32 = require('bech32')
var bufferEquals = require('buffer-equals')
var createHash = require('create-hash')
var secp256k1 = require('secp256k1')
var varuint = require('varuint-bitcoin')

function sha256 (b) {
  return createHash('sha256').update(b).digest()
}
function hash256 (buffer) {
  return sha256(sha256(buffer))
}
function hash160 (buffer) {
  return createHash('ripemd160').update(sha256(buffer)).digest()
}

function encodeSignature (signature, recovery, compressed, segwitType) {
  if (segwitType !== undefined) {
    recovery += 8
    if (segwitType === 'bech32') recovery += 4
  } else {
    if (compressed) recovery += 4
  }
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
}

function decodeSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  var flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 15 || flagByte < 0) throw new Error('Invalid signature parameter')

  return {
    compressed: !!(flagByte & 12),
    segwitType: !(flagByte & 8) ? null : (!(flagByte & 4) ? 'base58' : 'bech32'),
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

function magicHash (message, messagePrefix) {
  messagePrefix = messagePrefix || '\u0018Bitcoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) messagePrefix = Buffer.from(messagePrefix, 'utf8')

  var messageVISize = varuint.encodingLength(message.length)
  var buffer = Buffer.allocUnsafe(messagePrefix.length + messageVISize + message.length)
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  buffer.write(message, messagePrefix.length + messageVISize)
  return hash256(buffer)
}

function sign (message, privateKey, compressed, messagePrefix, segwitType) {
  if (segwitType && segwitType !== 'base58' && segwitType !== 'bech32') {
    throw new Error('Unrecognized segwitType: use "base58" or "bech32"')
  }
  var hash = magicHash(message, messagePrefix)
  var sigObj = secp256k1.sign(hash, privateKey)
  return encodeSignature(sigObj.signature, sigObj.recovery, compressed, segwitType)
}

function verify (message, address, signature, messagePrefix) {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64')

  var parsed = decodeSignature(signature)
  var hash = magicHash(message, messagePrefix)
  var publicKey = secp256k1.recover(hash, parsed.signature, parsed.recovery, parsed.compressed)
  var publicKeyHash = hash160(publicKey)
  var actual, expected

  if (parsed.segwitType) {
    if (parsed.segwitType === 'base58') {
      var redeemScript = Buffer.concat([Buffer.from('0014', 'hex'), publicKeyHash])
      var redeemScriptHash = hash160(redeemScript)
      actual = redeemScriptHash
      expected = bs58check.decode(address).slice(1)
    } else if (parsed.segwitType === 'bech32') {
      var result = bech32.decode(address)
      var data = bech32.fromWords(result.words.slice(1))
      actual = publicKeyHash
      expected = Buffer.from(data)
    }
  } else {
    actual = publicKeyHash
    expected = bs58check.decode(address).slice(1)
  }

  return bufferEquals(actual, expected)
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  verify: verify
}
