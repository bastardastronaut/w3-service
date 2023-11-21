import {
  sha256,
  concat,
  toBeArray,
  getBytes,
  zeroPadValue,
  Provider,
  Contract,
  Wallet,
  Signer,
  hexlify,
  isHexString,
  encodeBase64,
  decodeBase64,
  HDNodeWallet,
  Mnemonic,
} from "ethers";
import * as Name from "w3name";

import {
  generateKeyPair,
  concatBytes,
  writeWith,
  getNameFromSeed,
  importPublicKey,
  readSeedValue,
  importPrivateKey,
  importEncryptionKey,
  exportPublicKey,
  exportPrivateKey,
  exchangeKeys,
  encrypt,
  decrypt,
  exchangeKeysAndEncrypt,
  exchangeKeysAndDecrypt,
  deriveBits,
  getTimestamp,
  resolveSlot,
} from "./utils";

import {
  messageSchema,
  buildSchema,
  applySchema,
  Schema,
  AppliedSchema,
} from "./schema";

export default class KeyHolder {
  protected wallet: Wallet | HDNodeWallet;
  private _signingKey?: {
    publicKey: CryptoKey | string;
    privateKey: CryptoKey | string;
  };

  get publicKey() {
    if (
      !this._signingKey?.publicKey ||
      typeof this._signingKey.publicKey === "string"
    )
      throw new Error("key not present?");
    return this._signingKey.publicKey;
  }

  get address() {
    return this.wallet.address;
  }

  constructor(
    privateKey: string,
    signingKey?: {
      publicKey: CryptoKey | string;
      privateKey: CryptoKey | string;
    }
  ) {
    this._signingKey = signingKey;

    this.wallet = isHexString(privateKey)
      ? new Wallet(privateKey)
      : privateKey.length > 100
      ? this.importIdentity(privateKey)
      : HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(privateKey));
  }

  protected get signingKey(): { publicKey: CryptoKey; privateKey: CryptoKey } {
    if (
      !this._signingKey ||
      typeof this._signingKey.privateKey === "string" ||
      typeof this._signingKey.publicKey === "string"
    )
      throw new Error("key not set yet");

    return this._signingKey as { publicKey: CryptoKey; privateKey: CryptoKey };
  }

  getContractRunner(address: string, abi: any, provider: Provider) {
    return new Contract(
      address,
      abi,
      new Wallet(this.wallet.privateKey, provider)
    );
  }

  private parseOrGenerateKey() {
    if (!this._signingKey) {
      return generateKeyPair().then(({ privateKey, publicKey }) => [
        privateKey,
        publicKey,
      ]);
    }

    if (typeof this._signingKey.privateKey === "string") {
      return Promise.all([
        importPrivateKey(this._signingKey.privateKey),
        importPublicKey(this._signingKey.publicKey as string),
      ]);
    }

    return Promise.resolve([
      this._signingKey.privateKey,
      this._signingKey.publicKey,
    ]);
  }

  initialize() {
    return this.parseOrGenerateKey().then(([privateKey, publicKey]) => {
      this._signingKey = { privateKey, publicKey };
    });
  }

  writeAt(
    message: Uint8Array,
    slot: Uint8Array | Name.WritableName,
    increment = true
  ) {
    return resolveSlot(slot).then((w3name) =>
      writeWith(this.wallet, this.signingKey.publicKey)(
        message,
        w3name,
        increment
      )
    );
  }

  encryptAndWrite(
    message: Uint8Array,
    slot: Uint8Array,
    publicKey?: Uint8Array | CryptoKey,
    increment = false
  ) {
    return (
      publicKey
        ? exchangeKeys(publicKey, this.signingKey.privateKey)
        : importEncryptionKey(getBytes(this.wallet.privateKey))
    )
      .then((encryptionKey) =>
        encrypt(encryptionKey, slot.slice(0, 12), message)
      )
      .then((cipherText) => this.writeAt(new Uint8Array(cipherText), slot));
  }

  signMessage(message: Uint8Array) {
    return this.wallet.signMessage(message);
  }

  /*
   * requires signature to be in 1st position.
   * */
  buildSchemaAndSign(schema: Schema, data: AppliedSchema): Promise<Uint8Array> {
    if (schema.timestamp) {
      data.timestamp = getTimestamp();
    }

    const message = buildSchema(schema, data);

    return this.wallet
      .signMessage(message)
      .then((signature) =>
        concatBytes([getBytes(signature), message])
      );
  }

  readAndDecrypt(slot: Uint8Array) {
    return readSeedValue(slot).then((slotData) => {
      if (!slotData) return null;
      const signature = slotData.slice(0, 65);
      const { from, publicKey, message } = applySchema(
        messageSchema,
        slotData.slice(65)
      );
      if (from === this.wallet.address.toLowerCase())
        return this.receive(message as Uint8Array, slot);
      return this.receive(message as Uint8Array, slot, publicKey as Uint8Array);
    });
  }

  receive(cipherText: Uint8Array, slot: Uint8Array, publicKey?: Uint8Array) {
    return (
      publicKey
        ? exchangeKeys(publicKey, this.signingKey.privateKey)
        : importEncryptionKey(getBytes(this.wallet.privateKey))
    ).then((encryptionKey) =>
      decrypt(encryptionKey, slot.slice(0, 12), cipherText)
    );
  }

  createSecret(data: Uint8Array) {
    return exportPrivateKey(this.signingKey.privateKey).then((privateKey) =>
      getBytes(sha256(concat([data, new TextEncoder().encode(privateKey)])))
    );
  }

  createCommonSecret(data: Uint8Array, publicKey: Uint8Array) {
    return deriveBits(publicKey, this.signingKey.privateKey).then(
      (commonBits) => sha256(concat([data, commonBits]))
    );
  }

  private importIdentity(identity: string) {
    const identityBytes = decodeBase64(identity);
    const dc = new TextDecoder();

    this._signingKey = {
      privateKey: dc.decode(identityBytes.slice(32, 410)),
      publicKey: dc.decode(identityBytes.slice(410)),
    };

    return new Wallet(hexlify(identityBytes.slice(0, 32)));
  }

  exportIdentity() {
    return Promise.all([
      exportPublicKey(this.signingKey.publicKey),
      exportPrivateKey(this.signingKey.privateKey),
    ]).then(([publicKey, privateKey]) => {
      const ec = new TextEncoder();

      return encodeBase64(
        concat([
          this.wallet.privateKey,
          ec.encode(privateKey),
          ec.encode(publicKey),
        ])
      );
    });
  }
}
