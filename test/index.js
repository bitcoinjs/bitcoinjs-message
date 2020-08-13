const test = require('tape').test
const bitcoin = require('bitcoinjs-lib')
const BigInteger = require('bigi')
const message = require('../')

const fixtures = require('./fixtures.json')

function getMessagePrefix (networkName) {
  return fixtures.networks[networkName]
}

fixtures.valid.magicHash.forEach(f => {
  test(
    'produces the magicHash for "' + f.message + '" (' + f.network + ')',
    t => {
      const actual = message.magicHash(f.message, getMessagePrefix(f.network))
      t.same(actual.toString('hex'), f.magicHash)
      t.end()
    }
  )
})

fixtures.valid.sign.forEach(f => {
  test('sign: ' + f.description, t => {
    const pk = new bitcoin.ECPair(new BigInteger(f.d)).d.toBuffer(32)
    let signature = message.sign(
      f.message,
      pk,
      false,
      getMessagePrefix(f.network)
    )
    t.same(signature.toString('base64'), f.signature)

    if (f.compressed) {
      signature = message.sign(f.message, pk, true, getMessagePrefix(f.network))
      t.same(signature.toString('base64'), f.compressed.signature)
    }

    if (f.segwit) {
      if (f.segwit.P2SH_P2WPKH) {
        signature = message.sign(
          f.message,
          pk,
          true,
          getMessagePrefix(f.network),
          { segwitType: 'p2sh(p2wpkh)' }
        )
        t.same(signature.toString('base64'), f.segwit.P2SH_P2WPKH.signature)
      }
      if (f.segwit.P2WPKH) {
        signature = message.sign(
          f.message,
          pk,
          true,
          getMessagePrefix(f.network),
          { segwitType: 'p2wpkh' }
        )
        t.same(signature.toString('base64'), f.segwit.P2WPKH.signature)
      }
    }

    t.end()
  })
})

fixtures.valid.verify.forEach(f => {
  test(
    'verifies a valid signature for "' + f.message + '" (' + f.network + ')',
    t => {
      t.true(
        message.verify(
          f.message,
          f.address,
          f.signature,
          getMessagePrefix(f.network)
        )
      )

      if (f.network === 'bitcoin') {
        // defaults to bitcoin network
        t.true(message.verify(f.message, f.address, f.signature))
      }

      if (f.compressed) {
        t.true(
          message.verify(
            f.message,
            f.compressed.address,
            f.compressed.signature,
            getMessagePrefix(f.network)
          )
        )
      }

      if (f.segwit) {
        if (f.segwit.P2SH_P2WPKH) {
          t.true(
            message.verify(
              f.message,
              f.segwit.P2SH_P2WPKH.address,
              f.segwit.P2SH_P2WPKH.signature,
              getMessagePrefix(f.network)
            )
          )
        }
        if (f.segwit.P2WPKH) {
          t.true(
            message.verify(
              f.message,
              f.segwit.P2WPKH.address,
              f.segwit.P2WPKH.signature,
              getMessagePrefix(f.network)
            )
          )
        }
      }

      t.end()
    }
  )
})

fixtures.valid.recover.forEach(f => {
  test(
    'recovers a valid signature for "' + f.message + '" (' + f.network + ')',
    t => {
      t.true(
        message.recover(
          f.message,
          f.address,
          f.signature,
          getMessagePrefix(f.network)
        )
      )

      if (f.network === 'bitcoin') {
        // defaults to bitcoin network
        t.true(message.recover(f.message, f.address, f.signature))
      }

      if (f.compressed) {
        t.true(
          message.recover(
            f.message,
            f.compressed.address,
            f.compressed.signature,
            getMessagePrefix(f.network)
          )
        )
      }

      if (f.segwit) {
        if (f.segwit.P2SH_P2WPKH) {
          t.true(
            message.recover(
              f.message,
              f.segwit.P2SH_P2WPKH.address,
              f.segwit.P2SH_P2WPKH.signature,
              getMessagePrefix(f.network)
            )
          )
        }
        if (f.segwit.P2WPKH) {
          t.true(
            message.recover(
              f.message,
              f.segwit.P2WPKH.address,
              f.segwit.P2WPKH.signature,
              getMessagePrefix(f.network)
            )
          )
        }
      }

      t.end()
    }
  )
})

fixtures.invalid.signature.forEach(f => {
  test('decode signature: throws on ' + f.hex, t => {
    t.throws(() => {
      message.verify(null, null, Buffer.from(f.hex, 'hex'), null)
    }, new RegExp('^Error: ' + f.exception + '$'))
    t.end()
  })
})

fixtures.invalid.verify.forEach(f => {
  test(f.description, t => {
    t.false(
      message.verify(
        f.message,
        f.address,
        f.signature,
        getMessagePrefix('bitcoin')
      )
    )
    t.end()
  })
})

fixtures.randomSig.forEach(f => {
  test(f.description, t => {
    const keyPair = bitcoin.ECPair.fromWIF(f.wif)
    const privateKey = keyPair.d.toBuffer(32)
    const address = keyPair.getAddress()
    f.signatures.forEach(s => {
      const signature = message.sign(
        f.message,
        privateKey,
        keyPair.compressed,
        { extraEntropy: Buffer.from(s.sigData, 'base64') }
      )
      t.true(message.verify(f.message, address, signature))
    })
    t.end()
  })
})
