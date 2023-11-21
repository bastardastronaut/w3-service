import { Provider, Contract, Wallet, HDNodeWallet } from "ethers";
import * as Name from "w3name";
import { Schema, AppliedSchema } from "./schema";
export default class KeyHolder {
    protected wallet: Wallet | HDNodeWallet;
    private _signingKey?;
    get publicKey(): CryptoKey;
    get address(): string;
    constructor(privateKey: string, signingKey?: {
        publicKey: CryptoKey | string;
        privateKey: CryptoKey | string;
    });
    protected get signingKey(): {
        publicKey: CryptoKey;
        privateKey: CryptoKey;
    };
    getContractRunner(address: string, abi: any, provider: Provider): Contract;
    private parseOrGenerateKey;
    initialize(): Promise<void>;
    writeAt(message: Uint8Array, slot: Uint8Array | Name.WritableName, increment?: boolean): Promise<void>;
    encryptAndWrite(message: Uint8Array, slot: Uint8Array, publicKey?: Uint8Array | CryptoKey, increment?: boolean): Promise<void>;
    signMessage(message: Uint8Array): Promise<string>;
    buildSchemaAndSign(schema: Schema, data: AppliedSchema): Promise<Uint8Array>;
    readAndDecrypt(slot: Uint8Array): Promise<Uint8Array | null>;
    receive(cipherText: Uint8Array, slot: Uint8Array, publicKey?: Uint8Array): Promise<Uint8Array>;
    createSecret(data: Uint8Array): Promise<Uint8Array>;
    createCommonSecret(data: Uint8Array, publicKey: Uint8Array): Promise<string>;
    private importIdentity;
    exportIdentity(): Promise<string>;
}
