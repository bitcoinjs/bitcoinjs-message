interface SignatureOptions {
  segwitType: string;
  extraEntropy: Buffer | null;
}

export function magicHash(message: string, messagePrefix?: string): Buffer;

export function sign(
  message: string,
  privateKey: Buffer,
  compressed?: boolean,
  sigOptions?: SignatureOptions
): Buffer;

export function verify(
  message: string,
  address: string,
  signature: string | Buffer,
  messagePrefix?: string
): boolean;

export function recover(
  message: string,
  address: string,
  signature: string | Buffer,
  messagePrefix?: string
): string;
