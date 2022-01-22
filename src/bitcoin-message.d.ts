/// <reference types="node" />
export interface SignOptions {
    segwitType?: string;
    extraEntropy?: Buffer;
    messagePrefixArg?: string;
}
export declare function magicHash(message: Buffer | string, messagePrefix?: Buffer | string | null): Buffer;
export declare function sign(message: Buffer | string, privateKey: Buffer | any, compressed: boolean, messagePrefix?: SignOptions | Buffer | string, sigOptions?: SignOptions): Buffer;
export declare function signAsync(message: Buffer | string, privateKey: Buffer | any, compressed: boolean, messagePrefix: string, sigOptions?: SignOptions): Promise<Buffer>;
export declare function verify(message: Buffer | string, address: string, signature: Buffer | string, messagePrefix?: Buffer | string | null, checkSegwitAlways?: boolean): boolean;
