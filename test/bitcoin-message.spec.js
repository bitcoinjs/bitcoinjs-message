"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require("assert");
const mocha_1 = require("mocha");
const ecpair_1 = require("ecpair");
const bs58check = require("bs58check");
const bech32_1 = require("bech32");
const bitcoinjs = require("bitcoinjs-lib");
const tinySecp256k1 = require("tiny-secp256k1");
const crypto_1 = require("../src/crypto");
const message = require("../src");
const fixtures = require("./fixtures.json");
const BigInteger = require('bigi');
const ECPair = (0, ecpair_1.default)(tinySecp256k1);
function getMessagePrefix(networkName) {
    // @ts-ignore
    return fixtures.networks[networkName];
}
(0, mocha_1.describe)('magicHash', () => {
    fixtures.valid.magicHash.forEach((f) => {
        (0, mocha_1.it)('produces the magicHash for "' + f.message + '" (' + f.network + ')', () => {
            const actual = message.magicHash(f.message, getMessagePrefix(f.network));
            assert.strictEqual(actual.toString('hex'), f.magicHash);
        });
    });
});
(0, mocha_1.describe)('sign', () => {
    fixtures.valid.sign.forEach((f) => {
        (0, mocha_1.it)(f.description, async () => {
            const pk = ECPair.fromPrivateKey(new BigInteger(f.d).toBuffer(32)).privateKey;
            const signer = (hash, ex) => tinySecp256k1.signRecoverable(hash, pk, ex);
            const signerAsync = async (hash, ex) => tinySecp256k1.signRecoverable(hash, pk, ex);
            let signature = message.sign(f.message, pk, false, getMessagePrefix(f.network));
            const signature2 = message.sign(f.message, { sign: signer }, false, getMessagePrefix(f.network));
            const signature3 = await message.signAsync(f.message, { sign: signerAsync }, false, getMessagePrefix(f.network));
            const signature4 = await message.signAsync(f.message, { sign: signer }, false, getMessagePrefix(f.network));
            const signature5 = await message.signAsync(f.message, pk, false, getMessagePrefix(f.network));
            assert.strictEqual(signature.toString('base64'), f.signature);
            assert.strictEqual(signature2.toString('base64'), f.signature);
            assert.strictEqual(signature3.toString('base64'), f.signature);
            assert.strictEqual(signature4.toString('base64'), f.signature);
            assert.strictEqual(signature5.toString('base64'), f.signature);
            if (f.compressed) {
                signature = message.sign(f.message, pk, true, getMessagePrefix(f.network));
                assert.strictEqual(signature.toString('base64'), f.compressed.signature);
            }
            if (f.segwit) {
                if (f.segwit.P2SH_P2WPKH) {
                    signature = message.sign(f.message, pk, true, getMessagePrefix(f.network), { segwitType: 'p2sh(p2wpkh)' });
                    assert.strictEqual(signature.toString('base64'), f.segwit.P2SH_P2WPKH.signature);
                }
                if (f.segwit.P2WPKH) {
                    signature = message.sign(f.message, pk, true, getMessagePrefix(f.network), { segwitType: 'p2wpkh' });
                    assert.strictEqual(signature.toString('base64'), f.segwit.P2WPKH.signature);
                }
            }
        });
    });
});
(0, mocha_1.describe)('verify', () => {
    fixtures.valid.verify.forEach((f) => {
        (0, mocha_1.it)('a valid signature for "' + f.message + '" (' + f.network + ')', () => {
            assert.strictEqual(message.verify(f.message, f.address, f.signature, getMessagePrefix(f.network)), true);
            if (f.network === 'bitcoin') {
                // defaults to bitcoin network
                assert.strictEqual(message.verify(f.message, f.address, f.signature), true);
            }
            if (f.compressed) {
                assert.strictEqual(message.verify(f.message, f.compressed.address, f.compressed.signature, getMessagePrefix(f.network)), true);
            }
            if (f.segwit) {
                if (f.segwit.P2SH_P2WPKH) {
                    assert.strictEqual(message.verify(f.message, f.segwit.P2SH_P2WPKH.address, f.segwit.P2SH_P2WPKH.signature, getMessagePrefix(f.network)), true);
                    assert.strictEqual(message.verify(f.message, f.segwit.P2SH_P2WPKH.address, f.segwit.P2SH_P2WPKH.signature.replace(/^./, 'I'), getMessagePrefix(f.network), true), true);
                }
                if (f.segwit.P2WPKH) {
                    assert.strictEqual(message.verify(f.message, f.segwit.P2WPKH.address, f.segwit.P2WPKH.signature, getMessagePrefix(f.network)), true);
                    assert.strictEqual(message.verify(f.message, f.segwit.P2WPKH.address, f.segwit.P2WPKH.signature.replace(/^./, 'I'), getMessagePrefix(f.network), true), true);
                }
            }
        });
    });
});
(0, mocha_1.describe)('decode signature', () => {
    fixtures.invalid.signature.forEach((f) => {
        (0, mocha_1.it)('throws on ' + f.hex, () => {
            assert.throws(() => {
                message.verify(null, null, Buffer.from(f.hex, 'hex'), null);
            }, new RegExp('^Error: ' + f.exception + '$'));
        });
    });
});
(0, mocha_1.describe)('verify signature', () => {
    fixtures.invalid.verify.forEach((f) => {
        (0, mocha_1.it)(f.description, () => {
            assert.strictEqual(message.verify(f.message, f.address, f.signature, getMessagePrefix('bitcoin')), false);
        });
    });
});
(0, mocha_1.describe)('verify random signature', () => {
    fixtures.randomSig.forEach((f) => {
        (0, mocha_1.it)(f.description, () => {
            const keyPair = ECPair.fromWIF(f.wif);
            const address = bitcoinjs.payments.p2pkh({
                pubkey: keyPair.publicKey,
            }).address;
            f.signatures.forEach((s) => {
                const signature = message.sign(f.message, keyPair.privateKey, keyPair.compressed, { extraEntropy: Buffer.from(s.sigData, 'base64') });
                assert.strictEqual(message.verify(f.message, address, signature), true);
            });
        });
    });
});
(0, mocha_1.describe)('Check that compressed signatures can be verified as segwit', () => {
    const keyPair = ECPair.makeRandom();
    const publicKeyHash = (0, crypto_1.hash160)(keyPair.publicKey);
    const p2shp2wpkhRedeemHash = segwitRedeemHash(publicKeyHash);
    const p2pkhAddress = bitcoinjs.payments.p2pkh({
        pubkey: keyPair.publicKey,
    }).address;
    const p2shp2wpkhAddress = bs58check.encode(Buffer.concat([Buffer.from([5]), p2shp2wpkhRedeemHash]));
    const p2wpkhAddress = bech32_1.bech32.encode('bc', [0].concat(bech32_1.bech32.toWords(publicKeyHash)));
    const msg = 'Sign me';
    const signature = message.sign(msg, keyPair.privateKey, true);
    // Make sure it verifies
    assert.strictEqual(message.verify(msg, p2pkhAddress, signature), true);
    // Make sure it verifies even with checkSegwitAlways
    assert.strictEqual(message.verify(msg, p2pkhAddress, signature, null, true), true);
    // Check segwit addresses with true
    assert.strictEqual(message.verify(msg, p2shp2wpkhAddress, signature, null, true), true);
    assert.strictEqual(message.verify(msg, p2wpkhAddress, signature, null, true), true);
    // Check segwit with false
    assert.strictEqual(message.verify(msg, p2shp2wpkhAddress, signature) === false, true);
    assert.throws(() => {
        message.verify(msg, p2wpkhAddress, signature);
    }, new RegExp('^Error: Non-base58 character$'));
    const signatureUncompressed = message.sign(msg, keyPair.privateKey, false);
    assert.throws(() => {
        message.verify(msg, p2shp2wpkhAddress, signatureUncompressed, null, true);
    }, new RegExp('^Error: checkSegwitAlways can only be used with a compressed pubkey signature flagbyte$'));
});
(0, mocha_1.describe)('Check that invalid segwitType fails', () => {
    const keyPair = ECPair.fromWIF('L3n3e2LggPA5BuhXyBetWGhUfsEBTFe9Y6LhyAhY2mAXkA9jNE56');
    assert.throws(() => {
        message.sign('Sign me', keyPair.privateKey, true, { segwitType: 'XYZ' });
    }, new RegExp('Unrecognized segwitType: use "p2sh\\(p2wpkh\\)" or "p2wpkh"'));
});
(0, mocha_1.describe)('Check that Buffers and wrapped Strings are accepted', () => {
    const keyPair = ECPair.fromWIF('L3n3e2LggPA5BuhXyBetWGhUfsEBTFe9Y6LhyAhY2mAXkA9jNE56');
    // eslint-disable-next-line no-new-wrappers
    const sig = message.sign(Buffer.from('Sign me', 'utf8'), keyPair.privateKey, true, Buffer.from([1, 2, 3, 4]), { segwitType: 'p2wpkh' });
    assert.strictEqual(sig.toString('hex'), '276e5e5e75196dd93bba7b98f29f944156286d94cb34c376822c6ebc93e08d7b2d177e1f2215b2879caee53f39a376cf350ffdca70df4398a12d5b5adaf3b0f0bc');
});
function segwitRedeemHash(publicKeyHash) {
    const redeemScript = Buffer.concat([
        Buffer.from('0014', 'hex'),
        publicKeyHash,
    ]);
    return (0, crypto_1.hash160)(redeemScript);
}
