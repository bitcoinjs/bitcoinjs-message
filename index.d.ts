interface SignatureOptions {
  segwitType?: 'p2wpkh' | 'p2sh(p2wpkh)';
  extraEntropy?: Buffer;
}

export function magicHash(
  message: string | Buffer,
  messagePrefix?: string
): Buffer;

// sign function is overloaded
export function sign(
  message: string | Buffer,
  privateKey: Buffer,
  compressed?: boolean,
  sigOptions?: SignatureOptions
): Buffer;
export function sign(
  message: string | Buffer,
  privateKey: Buffer,
  compressed?: boolean,
  messagePrefix?: string,
  sigOptions?: SignatureOptions
): Buffer;

export function verify(
  message: string | Buffer,
  address: string,
  signature: string | Buffer,
  messagePrefix?: string,
  checkSegwitAlways?: boolean
): boolean;
