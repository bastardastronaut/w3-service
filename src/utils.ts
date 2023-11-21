import {
  dataLength,
  stripZerosLeft,
  sha256,
  hexlify,
  encodeBase64,
  decodeBase64,
  toBeArray,
  zeroPadValue,
  Wallet,
  HDNodeWallet,
  getBytes,
  concat,
} from "ethers";
import { base36 } from "multiformats/bases/base36";

import { keys } from "libp2p-crypto";
import * as Name from "w3name";

const { subtle } = globalThis.crypto;

export function exportPublicKey(key: Uint8Array | CryptoKey) {
  return (
    key instanceof CryptoKey
      ? subtle.exportKey("spki", key)
      : subtle
          .importKey(
            "raw",
            key,
            { name: "ECDH", namedCurve: "P-521" },
            true,
            []
          )
          .then((_key) => subtle.exportKey("spki", _key))
  ).then(
    (exported) =>
      `-----BEGIN PUBLIC KEY-----\n${encodeBase64(
        new Uint8Array(exported)
      )}\n-----END PUBLIC KEY-----`
  );
}

export function exportPrivateKey(key: CryptoKey) {
  return subtle
    .exportKey("pkcs8", key)
    .then(
      (exported) =>
        `-----BEGIN PRIVATE KEY-----\n${encodeBase64(
          new Uint8Array(exported)
        )}\n-----END PRIVATE KEY-----`
    );
}

export function importPrivateKey(input: string) {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = input.substring(
    pemHeader.length,
    input.length - pemFooter.length
  );

  return subtle.importKey(
    "pkcs8",
    decodeBase64(pemContents),
    {
      name: "ECDH",
      namedCurve: "P-521",
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

export function importPublicKey(input: string) {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = input.substring(
    pemHeader.length,
    input.length - pemFooter.length
  );

  return subtle.importKey(
    "spki",
    decodeBase64(pemContents),
    {
      name: "ECDH",
      namedCurve: "P-521",
    },
    true,
    []
  );
}

export const getNameFromSeed = (seed: Uint8Array) =>
  keys
    .generateKeyPairFromSeed("Ed25519", seed, 2048)
    .then((keys) => new Name.WritableName(keys));

export const getNameAsBytes = (w3name: Name.Name) =>
  base36.baseDecode(w3name.toString());

export const parseNameFromBytes = (nameBytes: Uint8Array): string =>
  base36.baseEncode(nameBytes);

export const bytesToName = (nameBytes: Uint8Array): Name.Name =>
  Name.parse(base36.baseEncode(nameBytes));

export const loadName = (
  w3name: Name.WritableName | Name.Name
): Promise<Name.Revision | null> =>
  Name.resolve(w3name)
    .then((revision) => revision)
    .catch((e) => {
      if (e.message.startsWith("record not found")) {
        return null;
      }
      throw e;
    });

export const readValueAt = (w3name: Name.Name) =>
  loadName(w3name).then(
    (revision) => revision?.value && decodeBase64(revision.value)
  );

export const readValueAtAddress = (address: string) =>
  readValueAt(Name.parse(address));

export const readSeedValue = (seed: Uint8Array) =>
  getNameFromSeed(seed).then(readValueAt);

export const timeout = (n: number) => new Promise((r) => setTimeout(r, n));

export const exchangeKeys = (
  exportedPublicKey: Uint8Array | CryptoKey,
  privateKey: CryptoKey
): Promise<CryptoKey> =>
  (exportedPublicKey instanceof CryptoKey
    ? Promise.resolve(exportedPublicKey)
    : subtle.importKey(
        "raw",
        exportedPublicKey,
        { name: "ECDH", namedCurve: "P-521" },
        true,
        []
      )
  ).then((managerKey) =>
    subtle.deriveKey(
      { name: "ECDH", public: managerKey },
      privateKey,
      { name: "AES-GCM", length: 128 },
      true,
      ["encrypt", "decrypt"]
    )
  );

export const importEncryptionKey = (input: Uint8Array) =>
  subtle.importKey(
    "raw",
    input.slice(0, 16),
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );

export const deriveBits = (
  exportedPublicKey: Uint8Array | CryptoKey,
  privateKey: CryptoKey
) =>
  (exportedPublicKey instanceof CryptoKey
    ? Promise.resolve(exportedPublicKey)
    : subtle.importKey(
        "raw",
        exportedPublicKey,
        { name: "ECDH", namedCurve: "P-521" },
        true,
        []
      )
  )
    .then((managerKey) =>
      subtle.deriveBits({ name: "ECDH", public: managerKey }, privateKey, 256)
    )
    .then((commonBits) => new Uint8Array(commonBits));

export const exchangeKeysAndDecrypt = (
  exportedPublicKey: Uint8Array | CryptoKey,
  iv: Uint8Array,
  privateKey: CryptoKey,
  cipherText: Uint8Array
): Promise<Uint8Array> =>
  exchangeKeys(exportedPublicKey, privateKey)
    .then((encryptionKey) =>
      subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        },
        encryptionKey,
        cipherText
      )
    )
    .then((encodedData) => new Uint8Array(encodedData));

export const encrypt = (
  encryptionKey: CryptoKey,
  iv: Uint8Array,
  encodedData: Uint8Array
) =>
  subtle
    .encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      encryptionKey,
      encodedData
    )
    .then((cipherText) => new Uint8Array(cipherText));

export const decrypt = (
  encryptionKey: CryptoKey,
  iv: Uint8Array,
  cipherText: Uint8Array
) =>
  subtle
    .decrypt(
      {
        name: "AES-GCM",
        iv,
      },
      encryptionKey,
      cipherText
    )
    .then((message) => new Uint8Array(message));

export const exchangeKeysAndEncrypt = (
  exportedPublicKey: Uint8Array | CryptoKey,
  iv: Uint8Array,
  privateKey: CryptoKey,
  encodedData: Uint8Array
): Promise<Uint8Array> =>
  exchangeKeys(exportedPublicKey, privateKey)
    .then((encryptionKey) =>
      subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
        },
        encryptionKey,
        encodedData
      )
    )
    .then((cipherText) => new Uint8Array(cipherText));

export const resolveSlot = (slot: Uint8Array | Name.WritableName) =>
  slot instanceof Uint8Array ? getNameFromSeed(slot) : Promise.resolve(slot);

export const publishAt = (
  message: Uint8Array,
  revision: Name.WritableName,
  insert = true
) => {
  if (!insert) {
    // load current revision and increase
  }
};

export const writeAt = (
  message: Uint8Array,
  _slot: Uint8Array | Name.WritableName,
  increment = false
) => resolveSlot(_slot).then((slot) => _writeAt(message, slot, increment));

export const _writeAt = (
  message: Uint8Array,
  slot: Name.WritableName,
  increment = false
) => {
  const commit = (revision: Name.Revision) => Name.publish(revision, slot.key);

  const encodedMessage = encodeBase64(message);

  if (!increment) return Name.v0(slot, encodedMessage).then(commit);

  return loadName(slot)
    .then((revision) =>
      revision
        ? Name.increment(revision, encodedMessage)
        : Name.v0(slot, encodedMessage)
    )
    .then(commit);
};

export const concatBytes = (input: Uint8Array[]) => {
  const result = new Uint8Array(input.reduce((acc, i) => acc + i.length, 0));

  for (let seek = 0, i = 0; i < input.length; i += 1) {
    result.set(input[i], seek);
    seek += input[i].length;
  }

  return result;
};

export const writeWith =
  (wallet: Wallet | HDNodeWallet, publicKey: CryptoKey) =>
  (message: Uint8Array, slot: Name.WritableName, increment = true) =>
    subtle
      .exportKey("raw", publicKey)
      .then((exportedKey) => {
        const _message = concatBytes([
          getBytes(wallet.address),
          new Uint8Array(exportedKey),
          getBytes(zeroPadValue(toBeArray(getTimestamp()), 8)),
          message,
        ]);

        return Promise.all([
          Promise.resolve(_message),
          wallet.signMessage(_message),
        ]);
      })
      .then(([_message, signature]) =>
        writeAt(concatBytes([getBytes(signature), _message]), slot, increment)
      );

export const getSlotAt = (
  currentSlot: string | Uint8Array,
  i: number
): Uint8Array => {
  if (i === 0) return getBytes(currentSlot);
  return getSlotAt(sha256(hexlify(currentSlot)), i - 1);
};

export const findSlot = (
  slotRoot: Uint8Array,
  left = 0,
  right = 15
): Promise<[Name.WritableName, Uint8Array, number]> => {
  const middle = left + Math.floor((right - left) / 2);
  const slot = getSlotAt(slotRoot, middle);

  return timeout(500)
    .then(() => getNameFromSeed(slot))
    .then((slotName) =>
      loadName(slotName).then((revision) => {
        console.log(middle, left, right);

        if (middle === right) {
          if (revision === null) return [slotName, slot, middle];
          throw new Error();
        }

        if (revision === null) return findSlot(slotRoot, left, middle);

        return findSlot(slotRoot, middle + 1, right);
      })
    );
};

export const generateKeyPair = () =>
  subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, [
    "deriveKey",
    "deriveBits",
  ]);

export const getTimestamp = () => Math.floor(new Date().getTime() / 1000);

export const isEmpty = (data: Uint8Array | string) =>
  dataLength(stripZerosLeft(data)) === 0;
