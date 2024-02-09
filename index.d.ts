interface SignatureOptions {
  segwitType?: 'p2wpkh' | 'p2sh(p2wpkh)';
  extraEntropy?: Buffer;
}

export interface Signer {
  // param hash: 32 byte Buffer containing the digest of the message
  // param extraEntropy (optional): the 32 byte Buffer of the "extra data" part of RFC6979 nonces
  // returns object
  //   attribute signature: 64 byte Buffer, first 32 R value, last 32 S value of ECDSA signature
  //   attribute recovery: Number (integer) from 0 to 3 (inclusive), also known as recid, used for pubkey recovery
  signRecoverable(
    hash: Buffer,
    extraEntropy?: Buffer,
  ): { signature: Buffer; recovery: number };
}

export interface SignerAsync {
  // Same as Signer, but return is wrapped in a Promise
  signRecoverable(
    hash: Buffer,
    extraEntropy?: Buffer,
  ): Promise<{ signature: Buffer; recovery: number }>;
}

type RecoveryIdType = 0 | 1 | 2 | 3;
interface RecoverableSignature {
  signature: Uint8Array;
  recoveryId: RecoveryIdType;
}
interface TinySecp256k1Interface {
  signRecoverable(
    h: Uint8Array,
    d: Uint8Array,
    e?: Uint8Array,
  ): RecoverableSignature;
}

export interface MessageAPI {
  magicHash(message: string | Buffer, messagePrefix?: string): Buffer;

  // sign function is overloaded
  sign(
    message: string | Buffer,
    privateKey: Buffer | Signer,
    compressed?: boolean,
    sigOptions?: SignatureOptions,
  ): Buffer;
  sign(
    message: string | Buffer,
    privateKey: Buffer | Signer,
    compressed?: boolean,
    messagePrefix?: string,
    sigOptions?: SignatureOptions,
  ): Buffer;

  // signAsync function is overloaded
  signAsync(
    message: string | Buffer,
    privateKey: Buffer | SignerAsync | Signer,
    compressed?: boolean,
    sigOptions?: SignatureOptions,
  ): Promise<Buffer>;
  signAsync(
    message: string | Buffer,
    privateKey: Buffer | SignerAsync | Signer,
    compressed?: boolean,
    messagePrefix?: string,
    sigOptions?: SignatureOptions,
  ): Promise<Buffer>;

  verify(
    message: string | Buffer,
    address: string,
    signature: string | Buffer,
    messagePrefix?: string,
    checkSegwitAlways?: boolean,
  ): boolean;
}
export declare function MessageFactory(ecc: TinySecp256k1Interface): MessageAPI;
