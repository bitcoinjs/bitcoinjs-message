import * as bs58check from 'bs58check';
import { bech32 } from 'bech32';
import * as secp256k1 from 'tiny-secp256k1';
import * as varuint from 'varuint-bitcoin';

import { hash160, hash256 } from './crypto';

const SEGWIT_TYPES = {
  P2WPKH: 'p2wpkh',
  P2SH_P2WPKH: 'p2sh(p2wpkh)',
};

export interface SignOptions {
  segwitType?: string;
  extraEntropy?: Buffer;
  messagePrefixArg?: string;
}

type RecoveryIdType = 0 | 1 | 2 | 3;
interface Signature {
  compressed: boolean;
  segwitType: string | null;
  recovery: RecoveryIdType;
  signature: Buffer;
}

function encodeSignature(
  signature: Buffer,
  recovery: number,
  compressed: boolean,
  segwitType?: string,
): Buffer {
  if (segwitType !== undefined) {
    recovery += 8;
    if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4;
  } else {
    if (compressed) recovery += 4;
  }
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature]);
}

function decodeSignature(buffer: Buffer): Signature {
  if (buffer.length !== 65) throw new Error('Invalid signature length');

  const flagByte = buffer.readUInt8(0) - 27;
  if (flagByte > 15 || flagByte < 0) {
    throw new Error('Invalid signature parameter');
  }

  return {
    compressed: !!(flagByte & 12),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
      ? SEGWIT_TYPES.P2SH_P2WPKH
      : SEGWIT_TYPES.P2WPKH,
    recovery: (flagByte & 3) as RecoveryIdType,
    signature: buffer.slice(1),
  };
}

export function magicHash(
  message: Buffer | string,
  messagePrefix?: Buffer | string | null,
): Buffer {
  messagePrefix = messagePrefix || '\u0018Bitcoin Signed Message:\n';
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, 'utf8');
  }
  if (!Buffer.isBuffer(message)) {
    message = Buffer.from(message, 'utf8');
  }
  const messageVISize = varuint.encodingLength(message.length);
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length,
  );
  messagePrefix.copy(buffer, 0);
  varuint.encode(message.length, buffer, messagePrefix.length);
  message.copy(buffer, messagePrefix.length + messageVISize);
  return hash256(buffer);
}

function prepareSign(
  messagePrefixArg?: string | Buffer | SignOptions,
  sigOptions?: SignOptions,
): SignOptions {
  if (typeof messagePrefixArg === 'object' && sigOptions === undefined) {
    // @ts-ignore
    sigOptions = messagePrefixArg;
    messagePrefixArg = undefined;
  }
  let segwitType = (sigOptions || ({} as any)).segwitType;
  const extraEntropy = sigOptions && sigOptions.extraEntropy;
  if (
    segwitType &&
    (typeof segwitType === 'string' || segwitType instanceof String)
  ) {
    segwitType = segwitType.toLowerCase();
  }
  if (
    segwitType &&
    segwitType !== SEGWIT_TYPES.P2SH_P2WPKH &&
    segwitType !== SEGWIT_TYPES.P2WPKH
  ) {
    throw new Error(
      'Unrecognized segwitType: use "' +
        SEGWIT_TYPES.P2SH_P2WPKH +
        '" or "' +
        SEGWIT_TYPES.P2WPKH +
        '"',
    );
  }

  return {
    // @ts-ignore
    messagePrefixArg,
    segwitType,
    extraEntropy,
  };
}

function isSigner(obj: any): boolean {
  return obj && typeof obj.sign === 'function';
}

export function sign(
  message: Buffer | string,
  privateKey: Buffer | any,
  compressed: boolean,
  messagePrefix?: SignOptions | Buffer | string,
  sigOptions?: SignOptions,
): Buffer {
  const { messagePrefixArg, segwitType, extraEntropy } = prepareSign(
    messagePrefix,
    sigOptions,
  );
  const hash = magicHash(message, messagePrefixArg);
  const sigObj = isSigner(privateKey)
    ? privateKey.sign(hash, extraEntropy)
    : secp256k1.signRecoverable(hash, privateKey, extraEntropy);
  return encodeSignature(
    Buffer.from(sigObj.signature),
    sigObj.recoveryId,
    compressed,
    segwitType,
  );
}

export function signAsync(
  message: Buffer | string,
  privateKey: Buffer | any,
  compressed: boolean,
  messagePrefix: string,
  sigOptions?: SignOptions,
): Promise<Buffer> {
  let messagePrefixArg;
  let extraEntropy;
  let segwitType: string | undefined;
  return Promise.resolve()
    .then(() => {
      ({ messagePrefixArg, segwitType, extraEntropy } = prepareSign(
        messagePrefix,
        sigOptions,
      ));
      const hash = magicHash(message, messagePrefixArg);
      return isSigner(privateKey)
        ? privateKey.sign(hash, extraEntropy)
        : secp256k1.signRecoverable(hash, privateKey, extraEntropy);
    })
    .then((sigObj) => {
      return encodeSignature(
        Buffer.from(sigObj.signature),
        sigObj.recoveryId,
        compressed,
        segwitType,
      );
    });
}

function segwitRedeemHash(publicKeyHash: Buffer): Buffer {
  const redeemScript = Buffer.concat([
    Buffer.from('0014', 'hex'),
    publicKeyHash,
  ]);
  return hash160(redeemScript);
}

function decodeBech32(address: string): Buffer {
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));
  return Buffer.from(data);
}

export function verify(
  message: Buffer | string,
  address: string,
  signature: Buffer | string,
  messagePrefix?: Buffer | string | null,
  checkSegwitAlways?: boolean,
): boolean {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64');

  const parsed = decodeSignature(signature);

  if (checkSegwitAlways && !parsed.compressed) {
    throw new Error(
      'checkSegwitAlways can only be used with a compressed pubkey signature flagbyte',
    );
  }

  const hash = magicHash(message, messagePrefix);
  const publicKey = secp256k1.recover(
    hash,
    parsed.signature,
    parsed.recovery,
    parsed.compressed,
  );
  if (!publicKey) throw new Error('Public key is point at infinity!');
  const publicKeyHash = hash160(Buffer.from(publicKey));
  let actual;
  let expected;

  if (parsed.segwitType) {
    if (parsed.segwitType === SEGWIT_TYPES.P2SH_P2WPKH) {
      actual = segwitRedeemHash(publicKeyHash);
      expected = bs58check.decode(address).slice(1);
    } else {
      // parsed.segwitType === SEGWIT_TYPES.P2WPKH
      // must be true since we only return null, P2SH_P2WPKH, or P2WPKH
      // from the decodeSignature function.
      actual = publicKeyHash;
      expected = decodeBech32(address);
    }
  } else {
    if (checkSegwitAlways) {
      try {
        expected = decodeBech32(address);
        // if address is bech32 it is not p2sh
        return publicKeyHash.equals(expected);
      } catch (e) {
        const redeemHash = segwitRedeemHash(publicKeyHash);
        expected = bs58check.decode(address).slice(1);
        // base58 can be p2pkh or p2sh-p2wpkh
        return publicKeyHash.equals(expected) || redeemHash.equals(expected);
      }
    } else {
      actual = publicKeyHash;
      expected = bs58check.decode(address).slice(1);
    }
  }

  return actual.equals(expected);
}
