import * as createHash from 'create-hash';

export function sha256(buffer: Buffer): Buffer {
  return createHash('sha256').update(buffer).digest();
}
export function hash256(buffer: Buffer): Buffer {
  return sha256(sha256(buffer));
}
export function hash160(buffer: Buffer): Buffer {
  return createHash('ripemd160').update(sha256(buffer)).digest();
}
