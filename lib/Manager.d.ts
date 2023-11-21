import { Provider } from "ethers";
import { Request } from "./common";
import KeyHolder from "./KeyHolder";
import EventEmitter from "./EventEmitter";
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
    private processedRequests;
    private keyholder;
    private root;
    private slotIndex;
    private _slotRoot;
    private _rootName;
    private generateSlotData;
    private get slotRoot();
    private get rootName();
    private get nextSlot();
    get address(): string;
    constructor(privateKey: string, signingKey?: {
        publicKey: CryptoKey | string;
        privateKey: CryptoKey | string;
    });
    signMessage(message: Uint8Array): Promise<string>;
    getContractRunner(address: string, abi: any, provider: Provider): import("ethers").Contract;
    listen(onMessage?: (request: RequestEvent) => void, generateSlotData?: SlotRootDataFn): Promise<void>;
    private generateSlotRoot;
    private generateSlotContent;
    private publishSlot;
    private resetOrContinue;
    private loop;
    createSecret(data: Uint8Array): Promise<Uint8Array>;
    respondAt(slot: Uint8Array, publicKey: Uint8Array | CryptoKey, message: Uint8Array, increment?: boolean): Promise<void>;
}
export {};
