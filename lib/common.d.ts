import { AppliedSchema, Schema } from "./schema";
export declare const slotSchema: Schema;
export type Slot = AppliedSchema & {
    slotRoot: Uint8Array;
    publicKey: Uint8Array;
    publishedAt: number;
    data: Uint8Array;
};
export declare const signedSlotSchema: {
    signature: {
        type: any;
        byteLength: number;
    };
};
export type SignedSlot = Slot & {
    signature: string;
};
export declare const requestSchema: Schema;
export type Request = AppliedSchema & {
    publishedAt: number;
    publicKey: Uint8Array;
    from: string;
    signature: string;
    message: Uint8Array;
};
