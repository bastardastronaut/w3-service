type SchemaElement = {
    type: "buffer" | "number" | "string" | "repeating" | "hexstring" | "bignumber" | "boolean" | "nested";
    byteLength?: number;
    schema?: Schema;
};
export type Schema = {
    [key: string]: SchemaElement;
};
export type Primitive = Uint8Array | number | string | BigInt | boolean;
export type ArrayOfPrimitives = Array<{
    [key: string]: Primitive;
}>;
export type AppliedSchema<T = {}> = {
    [key: string]: Primitive | ArrayOfPrimitives | T[] | AppliedSchema;
};
export declare class ByteLengthViolation extends Error {
    constructor(message: string);
}
export declare const ec: TextEncoder;
export declare const dc: TextDecoder;
export declare function validateByteLength(data: ArrayBuffer, targetLength: number, minOnly?: boolean): void;
export declare function applySchema<T extends AppliedSchema>(schema: Schema, data: Uint8Array): T;
export declare function buildSchema(schema: Schema, _data: AppliedSchema): Uint8Array;
export declare const messageSchema: Schema;
export {};
