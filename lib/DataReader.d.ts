import * as Name from "w3name";
import { Request } from "./common";
import KeyHolder from "./KeyHolder";
export type GenericRequest = null | string | Request;
export declare function watchSlot(currentName: Name.WritableName, i?: number): Promise<GenericRequest>;
export declare const readWith: (seed: Uint8Array, keyholder: KeyHolder) => Promise<Uint8Array | null>;
