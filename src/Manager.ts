import {
  toBeArray,
  concat,
  Provider,
  verifyMessage,
  Wallet,
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
  timeout,
  getNameFromSeed,
  loadName,
  concatBytes,
  writeWith,
  importPublicKey,
} from "./utils";
import { Slot, slotSchema, requestSchema, Request } from "./common";
import { watchSlot, GenericRequest } from "./DataReader";
import KeyHolder from "./KeyHolder";
import EventEmitter from "./EventEmitter";

const { subtle } = globalThis.crypto;

const REQUEST_INTERVAL = 5 * 1000;

export type RequestEvent = {
  respond: (message: Uint8Array) => Promise<void>;
  keyholder: KeyHolder;
  message: Uint8Array;
  request: Request;
  slot: Uint8Array;
};

type SlotRootDataFn = (keyholder: KeyHolder, slotRoot: Uint8Array) => Promise<Uint8Array>;

export default class Manager extends EventEmitter<{
  request: RequestEvent;
}> {
  private processedRequests = 0;
  private keyholder: KeyHolder;
  private root: Uint8Array;
  private slotIndex: number = 0;
  private _slotRoot: Uint8Array | null = null;
  private _rootName: Name.WritableName | null = null;

  private generateSlotData: SlotRootDataFn = (keyholder: KeyHolder, slotRoot: Uint8Array) =>
    Promise.resolve(new Uint8Array());

  private get slotRoot() {
    if (!this._slotRoot) throw new Error("slot root not set yet");
    return this._slotRoot;
  }

  private get rootName() {
    if (!this._rootName) throw new Error("root not set yet");
    return this._rootName;
  }

  private get nextSlot() {
    this._slotRoot = getBytes(sha256(hexlify(this.slotRoot)));

    this.processedRequests += 1;

    // we can either do
    // batch processing of requests and use response chain
    // do like we did here, give signatures to party based on response

    return this.slotRoot;
  }

  get address() {
    return this.keyholder.address;
  }

  constructor(
    privateKey: string,
    signingKey?: {
      publicKey: CryptoKey | string;
      privateKey: CryptoKey | string;
    }
  ) {
    super();

    this.keyholder = new KeyHolder(privateKey, signingKey);

    this.root = getBytes(sha256(new TextEncoder().encode(privateKey)));
  }

  signMessage(message: Uint8Array) {
    return this.keyholder.signMessage(message);
  }

  getContractRunner(address: string, abi: any, provider: Provider) {
    return this.keyholder.getContractRunner(address, abi, provider);
  }

  listen(
    onMessage?: (request: RequestEvent) => void,
    generateSlotData?: SlotRootDataFn
  ) {
    if (onMessage) this.addEventListener("request", onMessage);
    if (generateSlotData) this.generateSlotData = generateSlotData;

    return this.keyholder
      .initialize()
      .then(() => getNameFromSeed(this.root))
      .then((rootName) => {
        this._rootName = rootName;
        console.log(
          `| ----------- ---------- APPLICATION ROOT ---------- ----------- |
| ${this._rootName.toString()} |
| ----------- ---------- ---------------- ---------- ----------- |
`
        );
      })
      .then(() => {
        this.loop();
      });
  }

  private generateSlotRoot() {
    this.processedRequests = 0;
    this._slotRoot = randomBytes(32);
  }

  private generateSlotContent() {
    this.generateSlotRoot();

    return Promise.all([
      subtle.exportKey("raw", this.keyholder.publicKey),
      this.generateSlotData(this.keyholder, this.slotRoot),
    ]).then(([exportedKey, data]) => {
      const slotContent = buildSchema(slotSchema, {
        slotRoot: this.slotRoot,
        publicKey: new Uint8Array(exportedKey),
        publishedAt: Math.round(new Date().getTime() / 1000),
        data,
        // should also reveal how many managers are watching the slot
        // more managers
        //  make binary search much faster
        //  less collision
        //  more frequent request processing
      });

      return Promise.all([
        Promise.resolve(slotContent),
        this.signMessage(slotContent),
      ]).then(([slotContent, signature]) =>
        encodeBase64(concat([signature, slotContent]))
      );
    });
  }

  private publishSlot = (encodedSlotContent: string) =>
    // Check if name exists..
    Name.resolve(this.rootName)
      .then((revision) => Name.increment(revision, encodedSlotContent))
      .catch((e) => {
        if (e.message.startsWith("record not found")) {
          return Name.v0(this.rootName, encodedSlotContent);
        }
        throw e;
      })
      .then((revision) => Name.publish(revision, this.rootName.key))
      .then(() => getNameFromSeed(this.slotRoot));

  private resetOrContinue = (request: GenericRequest): Promise<undefined> => {
    if (request === null) return Promise.resolve(undefined);

    // no need to wait for request procession to be completed before looking for the next slot.
    if (typeof request !== "string") {
      const slot = this.slotRoot.slice();
      this.keyholder
        .receive(request.message, slot, request.publicKey)
        .then((message) => {
          // storing processed requests...
          this.emit("request", {
            // then next 32 bytes are response slot
            message: message.slice(32), // this is TBD
            request: request as Request,
            slot,
            keyholder: this.keyholder,
            respond: (response: Uint8Array) =>
              this.keyholder.encryptAndWrite(
                response,
                message.slice(0, 32),
                request.publicKey
              ),
          });
        })
        .catch((e) => console.error(e));
    }

    return getNameFromSeed(this.nextSlot)
      .then((nextName) => watchSlot(nextName))
      .then(this.resetOrContinue);
  };

  private loop = () => {
    this.generateSlotContent()
      .then(this.publishSlot)
      // TODO: there are many safeguards you can apply
      // simplest one:
      // only allow requests from addresses that have assets on chain
      // and rate limit them heavily (max 1 game every 5 minutes)
      // since you control matchmaking you can make these restrictions
      // well, that still won't prevent them from pollution
      // but yes their responses can be simply disregarded.
      .then(watchSlot)
      .then(this.resetOrContinue)
      .then(this.loop);
  };

  createSecret(data: Uint8Array) {
    return this.keyholder.createSecret(data);
  }

  respondAt(
    slot: Uint8Array,
    publicKey: Uint8Array | CryptoKey,
    message: Uint8Array,
    increment = true
  ) {
    return this.keyholder.encryptAndWrite(message, slot, publicKey, increment);
  }
}
