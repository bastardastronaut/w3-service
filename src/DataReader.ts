import {
  toBeArray,
  zeroPadValue,
  concat,
  verifyMessage,
  getBytes,
  decodeBase64,
} from "ethers";
import * as Name from "w3name";

import { applySchema } from "./schema";
import { getNameFromSeed, loadName, timeout } from "./utils";
import { requestSchema, Request } from "./common";
import KeyHolder from "./KeyHolder";

// this is hardcoded into the application.
const REQUEST_INTERVAL = 5 * 1000;

export type GenericRequest = null | string | Request;

function parseRequest(input: string): GenericRequest {
  try {
    const req = applySchema<Request>(requestSchema, decodeBase64(input));

    if (
      req.from !==
      verifyMessage(
        getBytes(
          concat([
            req.from,
            req.publicKey,
            zeroPadValue(toBeArray(req.publishedAt), 8),
            req.message,
          ])
        ),
        req.signature
      ).toLowerCase()
    )
      return input;

    return req;
  } catch (e) {
    return input;
  }
}

export function watchSlot(
  currentName: Name.WritableName,
  i = 0
): Promise<GenericRequest> {
  if (i === 10) return Promise.resolve(null);

  return loadName(currentName).then(async (revision) => {
    if (revision === null) {
      console.log(`empty ${i} at ${currentName.toString()}`);
      return timeout(REQUEST_INTERVAL).then(() =>
        watchSlot(currentName, i + 1)
      );
    }

    const request = parseRequest(revision.value);

    // faulty value detected in slot. this is an error.
    if (!request) return revision.value;

    return request;
  });
}

class EmptyRevisionError extends Error {}

export const readWith = (
  seed: Uint8Array,
  keyholder: KeyHolder
): Promise<Uint8Array | null> =>
  getNameFromSeed(seed)
    .then(loadName)
    .then((revision) => {
      if (revision === null) throw new EmptyRevisionError();

      const { from, signature, message, publicKey, publishedAt } = applySchema<Request>(
        requestSchema,
        decodeBase64(revision.value)
      );

      /*
      if (
        verifyMessage(concatBytes([slotRoot, publicKey]), signature) !==
          from
      )
        throw new Error("malformed application root value");*/

      return keyholder.receive(message, seed, publicKey);
    })
    .catch((e) => {
      if (e instanceof EmptyRevisionError) return null;
      throw e;
    });
