import { AppliedSchema, Schema } from "./schema";

export const slotSchema: Schema = {
  slotRoot: {
    type: "buffer",
    byteLength: 32,
  },
  publicKey: {
    type: "buffer",
    byteLength: 133,
  },
  publishedAt: {
    type: 'number',
    byteLength: 8,
  },
  data: {
    // arbitrary data that can be added to announcement
    type: 'buffer'
  }
};

export type Slot = AppliedSchema & {
  slotRoot: Uint8Array;
  publicKey: Uint8Array;
  publishedAt: number;
  data: Uint8Array;
};

export const signedSlotSchema = {
  signature: {
    type: "hexstring" as any,
    byteLength: 65,
  },
  ...slotSchema,
};

export type SignedSlot = Slot & {
  signature: string;
};

export const requestSchema: Schema = {
  signature: {
    type: "hexstring",
    byteLength: 65,
  },
  from: {
    type: "hexstring",
    byteLength: 20,
  },
  publicKey: {
    type: "buffer",
    byteLength: 133,
  },
  publishedAt: {
    type: 'number',
    byteLength: 8,
  },
  message: { // TODO: rename to ciphertext
    type: "buffer",
  },
};

export type Request = AppliedSchema & {
  publishedAt: number;
  publicKey: Uint8Array;
  from: string;
  signature: string;
  message: Uint8Array;
};
