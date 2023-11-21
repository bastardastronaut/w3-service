import { SignedSlot } from "./common";
import KeyHolder from "./KeyHolder";
export declare const readRoot: (applicationRoot: string) => Promise<SignedSlot>;
export declare const readLastValue: (applicationRoot: string, keyholder: KeyHolder) => Promise<{
    from: string;
    signature: string;
    message: Uint8Array;
    publicKey: Uint8Array;
} | null>;
export declare const sendRequest: (applicationRoot: string, keyholder: KeyHolder, message: Uint8Array, expectResponse?: boolean, identity?: string) => Promise<null | Uint8Array>;
