import {
  concat,
  getBytes,
  toNumber,
  hexlify,
  toBeArray,
  zeroPadValue,
  Signer,
} from "ethers";

import { concatBytes } from "./utils";

const REPEATING_NUMBER_INDICATOR_BYTE_LENGTH = 4;

type SchemaElement = {
  type:
    | "buffer"
    | "number"
    | "string"
    | "repeating"
    | "hexstring"
    | "bignumber"
    | "boolean"
    | "nested";
  byteLength?: number; // if not provided, assuming end of data
  schema?: Schema; // for repeating and nested (experimental) type
};

export type Schema = {
  [key: string]: SchemaElement;
};

export type Primitive = Uint8Array | number | string | BigInt | boolean;
export type ArrayOfPrimitives = Array<{ [key: string]: Primitive }>;

export type AppliedSchema<T = {}> = {
  [key: string]: Primitive | ArrayOfPrimitives | T[] | AppliedSchema;
};

export class ByteLengthViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ByteLengthViolation";
  }
}

export const ec = new TextEncoder();
export const dc = new TextDecoder();

const removePadding = (input: Uint8Array) => {
  let i = 0;

  while (input[i] === 0 && i++ < input.length);

  return input.slice(i);
};

export function validateByteLength(
  data: ArrayBuffer,
  targetLength: number,
  minOnly = false
): void {
  if (minOnly && data.byteLength < targetLength) return;
  if (data.byteLength !== targetLength)
    throw new ByteLengthViolation(
      `data byte length verification falied. Target byte length: ${targetLength} Received byte length: ${data.byteLength}`
    );
}

function getByteLength(s: SchemaElement) {
  return s.type === "boolean"
    ? 1
    : s.type === "nested"
    ? Object.keys(s.schema as Schema).reduce(
        (sum, k) => sum + ((s.schema as Schema)[k].byteLength as number),
        0
      )
    : s.byteLength
    ? s.byteLength
    : 0;
}

function calculateRepeatingByteLength(schema: Schema, data: Uint8Array) {
  let dataLength = 0;
  for (const key in schema) {
    const s = schema[key];
    if (s.type === "repeating") {
      const n = toNumber(data.slice(dataLength, dataLength + 4));

      dataLength += 4;

      for (let i = 0; i < n; ++i) {
        dataLength += calculateRepeatingByteLength(
          s.schema as Schema,
          data.slice(dataLength)
        );
      }
    } else dataLength += getByteLength(s);
  }

  return dataLength;
}

export function applySchema<T extends AppliedSchema>(
  schema: Schema,
  data: Uint8Array
): T {
  const result: AppliedSchema = {};
  let needle = 0;

  for (const key in schema) {
    const s = schema[key];

    const byteLength = getByteLength(s);

    const dataEnd = byteLength ? needle + byteLength : data.byteLength;

    const value = data.slice(needle, dataEnd);

    if (s.type === "boolean") {
      result[key] = !!new Uint8Array(value)[0];
    } else if (s.type === "string") {
      result[key] = dc.decode(removePadding(new Uint8Array(value)));
    } else if (s.type === "number" && s.byteLength) {
      result[key] = toNumber(new Uint8Array(value));
    } else if (s.type === "buffer") {
      result[key] = new Uint8Array(value);
    } else if (s.type === "hexstring") {
      result[key] = hexlify(new Uint8Array(value));
    } else if (s.type === "bignumber") {
      result[key] = BigInt(hexlify(new Uint8Array(value)));
    } else if (s.type === "nested") {
      if (!s.schema) throw new Error(`no schema specified for ${key}`);
      (result[key] as AppliedSchema) = applySchema(s.schema, value);
    } else if (s.type === "repeating") {
      result[key] = [];
      if (!s.schema) throw new Error(`no schema specified for ${key}`);
      let i = 0;
      const n = toNumber(value.slice(0, 4));

      needle += 4;

      for (let i = 0; i < n; ++i) {
        const dataLength = calculateRepeatingByteLength(
          s.schema,
          data.slice(needle)
        );
        (result[key] as Array<AppliedSchema>).push(
          applySchema(s.schema, data.slice(needle, needle + dataLength))
        );
        needle += dataLength;
      }
    }

    needle = dataEnd;
  }

  return result as T;
}

export function buildSchema(schema: Schema, _data: AppliedSchema): Uint8Array {
  let result = new Uint8Array();
  const data = { ..._data };

  for (const key in schema) {
    if (!(key in data)) throw new Error(`Missing data: ${key}`);
    const s = schema[key];
    const d = data[key];

    if (s.type === "boolean") {
      result = concatBytes([result, new Uint8Array([d ? 1 : 0])]);
    } else if (s.type === "string") {
      const bytes = ec.encode(d as string);
      result = getBytes(
        concat([result, zeroPadValue(bytes, s.byteLength ?? bytes.length)])
      );
    } else if (s.type === "number" && s.byteLength) {
      if (typeof d !== "number") {
        throw new Error(`Wrong datatype for ${key}. Expected number.`);
      }

      // not sure why strict type is required
      result = getBytes(
        concat([result, zeroPadValue(toBeArray(d as number), s.byteLength)])
      );
    } else if (s.type === "bignumber" && s.byteLength) {
      // not sure why strict type is required
      result = getBytes(
        concat([result, zeroPadValue(toBeArray(d as number), s.byteLength)])
      );
    } else if (s.type === "buffer" || s.type === "hexstring") {
      const _d = getBytes(d as string | Uint8Array);

      // arraybuffer type, check for byte length
      if (s.byteLength) validateByteLength(_d.buffer, s.byteLength);

      result = concatBytes([result, _d]);
    } else if (s.type === "nested") {
      result = concatBytes([
        result,
        buildSchema(s.schema as Schema, d as AppliedSchema),
      ]);
    } else if (s.type === "repeating") {
      result = concatBytes([
        result,
        getBytes(
          zeroPadValue(toBeArray((d as Array<AppliedSchema>).length), 4)
        ),
        concatBytes(
          (d as Array<AppliedSchema>).map((_d) =>
            buildSchema(s.schema as Schema, _d)
          )
        ),
      ]);
      // result.bytelength is important here!
    } else {
      throw new Error(`Unprocessable schema type: ${s.type}`);
    }

    delete data[key];
  }

  if (Object.keys(data).length) {
    throw new Error(`invalid keys supplied to schema: ${Object.keys(data)}`);
  }

  return result;
}

export const messageSchema: Schema = {
  from: {
    type: "hexstring",
    byteLength: 20,
  },
  publicKey: {
    type: "buffer",
    byteLength: 133,
  },
  timestamp: {
    type: "number",
    byteLength: 8,
  },
  message: {
    type: "buffer",
  },
};
