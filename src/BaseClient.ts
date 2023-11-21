import {
  verifyMessage,
  concat,
  getBytes,
  randomBytes,
  sha256,
  hexlify,
  encodeBase64,
  decodeBase64,
} from "ethers";

import * as Name from "w3name";
import { buildSchema, applySchema, AppliedSchema, Schema } from "./schema";
import {
  getSlotAt,
  findSlot,
  getNameFromSeed,
  loadName,
  timeout,
  writeWith,
  concatBytes,
} from "./utils";
import { SignedSlot, requestSchema, Request, signedSlotSchema } from "./common";
import KeyHolder from "./KeyHolder";
import { watchSlot, GenericRequest } from "./DataReader";

export const readRoot = (applicationRoot: string) => {
  return loadName(Name.parse(applicationRoot)).then((revision) => {
    if (revision === null) throw new Error("application root not found");

    return applySchema<SignedSlot>(
      signedSlotSchema,
      decodeBase64(revision.value)
    );
  });
};

export const readLastValue = (
  applicationRoot: string,
  keyholder: KeyHolder
) => {
  return loadName(Name.parse(applicationRoot)).then((revision) => {
    if (revision === null) throw new Error("application root not found");

    const { signature, slotRoot, publicKey } = applySchema<SignedSlot>(
      signedSlotSchema,
      decodeBase64(revision.value)
    );

    return findSlot(slotRoot)
      .then(([a, b, c]) => getNameFromSeed(getSlotAt(slotRoot, c - 1)))
      .then(loadName)
      .then((revision) => {
        if (revision === null) return null;

        const { signature, from, message, publicKey } = applySchema<Request>(
          requestSchema,
          decodeBase64(revision.value)
        );

        return {
          from,
          signature,
          message,
          publicKey,
        };
      });
  });
};

export const sendRequest = (
  applicationRoot: string,
  keyholder: KeyHolder,
  message: Uint8Array,
  expectResponse = false,
  identity?: string
): Promise<null | Uint8Array> => {
  const responseSlot = randomBytes(32);

  return loadName(Name.parse(applicationRoot)).then((revision) => {
    if (revision === null) throw new Error("application root not found");

    const { signature, slotRoot, publicKey } = applySchema<SignedSlot>(
      signedSlotSchema,
      decodeBase64(revision.value)
    );

    if (
      identity &&
      verifyMessage(concatBytes([slotRoot, publicKey]), signature) !== identity
    )
      throw new Error("malformed application root value");

    return findSlot(slotRoot)
      .then(([slotName, slot]) =>
        keyholder.encryptAndWrite(
          concatBytes([responseSlot, message]),
          slot,
          publicKey
        )
      )
      .then((result): Promise<Uint8Array | null> => {
        if (!expectResponse) return Promise.resolve(null);

        return getNameFromSeed(responseSlot)
          .then((responseName) => watchSlot(responseName))
          .then((value: GenericRequest) => {
            if (value === null || typeof value === "string") return null;

            return keyholder.receive(
              value.message,
              responseSlot,
              value.publicKey
            );
          });
      });
  });
};
