/// <reference types="node" />
export declare function magicHash(message: Buffer | string, messagePrefix?: Buffer | string): Buffer;
export declare function sign(message: Buffer | string, privateKey: Buffer | any, compressed: boolean, messagePrefix: Buffer | string, sigOptions: any): Buffer;
export declare function signAsync(message: Buffer | string, privateKey: Buffer | any, compressed: boolean, messagePrefix: Buffer | string, sigOptions: any): Promise<Buffer>;
export declare function verify(message: Buffer | string, address: string, signature: Buffer, messagePrefix: Buffer | string, checkSegwitAlways?: boolean): any;
