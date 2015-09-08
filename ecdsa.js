/**
  * Recover a public key from a signature.
  *
  * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
  * Key Recovery Operation".
  *
  * http://www.secg.org/download/aid-780/sec1-v2.pdf
  */
var ecurve = require('ecurve')
var secp256k1 = ecurve.getCurveByName('secp256k1')
var typeforce = require('typeforce')

var BigInteger = require('bigi')

function __recoverPubKey (e, signature, i) {
  var n = secp256k1.n
  var G = secp256k1.G
  var r = signature.r
  var s = signature.s

  if (r.signum() <= 0 || r.compareTo(n) >= 0) throw new Error('Invalid r value')
  if (s.signum() <= 0 || s.compareTo(n) >= 0) throw new Error('Invalid s value')

  // A set LSB signifies that the y-coordinate is odd
  var isYOdd = i & 1

  // The more significant bit specifies whether we should use the
  // first or second candidate key.
  var isSecondKey = i >> 1

  // 1.1 Let x = r + jn
  var x = isSecondKey ? r.add(n) : r
  var R = secp256k1.pointFromX(isYOdd, x)

  // 1.4 Check that nR is at infinity
  var nR = R.multiply(n)
  if (!secp256k1.isInfinity(nR)) throw new Error('nR is not a valid curve point')

  // Compute r^-1
  var rInv = r.modInverse(n)

  // Compute -e from e
  var eNeg = e.negate().mod(n)

  // 1.6.1 Compute Q = r^-1 (sR -  eG)
  //               Q = r^-1 (sR + -eG)
  var Q = R.multiplyTwo(s, G, eNeg).multiply(rInv)

  secp256k1.validate(Q)

  return Q
}

var rPK_TYPE = typeforce.tuple(
  function Buffer256 (value) {
    return Buffer.isBuffer(value) && value.length === 32
  },
  {
    r: 'BigInteger',
    s: 'BigInteger'
  },
  function UInt2 (value) {
    return (value & 3) === value
  }
)

function recoverPubKey (hash, signature, i) {
  typeforce(rPK_TYPE, arguments)
  var e = BigInteger.fromBuffer(hash)

  return __recoverPubKey(e, signature, i)
}

/**
  * Calculate pubkey extraction parameter.
  *
  * When extracting a pubkey from a signature, we have to
  * distinguish four different cases. Rather than putting this
  * burden on the verifier, Bitcoin includes a 2-bit value with the
  * signature.
  *
  * This function simply tries all four cases and returns the value
  * that resulted in a successful pubkey recovery.
  */
function calcPubKeyRecoveryParam (hash, signature, Q) {
  var e = BigInteger.fromBuffer(hash)

  for (var i = 0; i < 4; i++) {
    var Qprime = __recoverPubKey(e, signature, i)

    // 1.6.2 Verify Q
    if (Qprime.equals(Q)) return i
  }

  throw new Error('Unable to find valid recovery factor')
}

module.exports = {
  calcPubKeyRecoveryParam: calcPubKeyRecoveryParam,
  recoverPubKey: recoverPubKey,

  // TODO: remove
  __curve: secp256k1
}
