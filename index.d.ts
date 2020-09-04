interface SignatureOptions {
  segwitType?: string;
  extraEntropy?: Buffer;
}

export function magicHash(
  message: string | Buffer,
  messagePrefix?: string
): Buffer;

export function sign(
  message: string | Buffer,
  privateKey: Buffer,
  compressed?: boolean,
  sigOptions?: SignatureOptions
): Buffer;

export function verify(
  message: string | Buffer,
  address: string,
  signature: string | Buffer,
  messagePrefix?: string,
  checkSegwitAlways?: boolean
): boolean;
