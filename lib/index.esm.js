import { encodeBase64, decodeBase64, getBytes, zeroPadValue, toBeArray, sha256, hexlify, dataLength, stripZerosLeft, toNumber, concat, verifyMessage, Contract, Wallet, isHexString, HDNodeWallet, Mnemonic, randomBytes } from 'ethers';
import * as Name from 'w3name';
import { base36 } from 'multiformats/bases/base36';
import { keys } from 'libp2p-crypto';

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

var subtle$1 = globalThis.crypto.subtle;
function exportPublicKey(key) {
    return (key instanceof CryptoKey
        ? subtle$1.exportKey("spki", key)
        : subtle$1
            .importKey("raw", key, { name: "ECDH", namedCurve: "P-521" }, true, [])
            .then(function (_key) { return subtle$1.exportKey("spki", _key); })).then(function (exported) {
        return "-----BEGIN PUBLIC KEY-----\n".concat(encodeBase64(new Uint8Array(exported)), "\n-----END PUBLIC KEY-----");
    });
}
function exportPrivateKey(key) {
    return subtle$1
        .exportKey("pkcs8", key)
        .then(function (exported) {
        return "-----BEGIN PRIVATE KEY-----\n".concat(encodeBase64(new Uint8Array(exported)), "\n-----END PRIVATE KEY-----");
    });
}
function importPrivateKey(input) {
    var pemHeader = "-----BEGIN PRIVATE KEY-----";
    var pemFooter = "-----END PRIVATE KEY-----";
    var pemContents = input.substring(pemHeader.length, input.length - pemFooter.length);
    return subtle$1.importKey("pkcs8", decodeBase64(pemContents), {
        name: "ECDH",
        namedCurve: "P-521",
    }, true, ["deriveKey", "deriveBits"]);
}
function importPublicKey(input) {
    var pemHeader = "-----BEGIN PUBLIC KEY-----";
    var pemFooter = "-----END PUBLIC KEY-----";
    var pemContents = input.substring(pemHeader.length, input.length - pemFooter.length);
    return subtle$1.importKey("spki", decodeBase64(pemContents), {
        name: "ECDH",
        namedCurve: "P-521",
    }, true, []);
}
var getNameFromSeed = function (seed) {
    return keys
        .generateKeyPairFromSeed("Ed25519", seed, 2048)
        .then(function (keys) { return new Name.WritableName(keys); });
};
var getNameAsBytes = function (w3name) {
    return base36.baseDecode(w3name.toString());
};
var parseNameFromBytes = function (nameBytes) {
    return base36.baseEncode(nameBytes);
};
var bytesToName = function (nameBytes) {
    return Name.parse(base36.baseEncode(nameBytes));
};
var loadName = function (w3name) {
    return Name.resolve(w3name)
        .then(function (revision) { return revision; })
        .catch(function (e) {
        if (e.message.startsWith("record not found")) {
            return null;
        }
        throw e;
    });
};
var readValueAt = function (w3name) {
    return loadName(w3name).then(function (revision) { return (revision === null || revision === void 0 ? void 0 : revision.value) && decodeBase64(revision.value); });
};
var readValueAtAddress = function (address) {
    return readValueAt(Name.parse(address));
};
var readSeedValue = function (seed) {
    return getNameFromSeed(seed).then(readValueAt);
};
var timeout = function (n) { return new Promise(function (r) { return setTimeout(r, n); }); };
var exchangeKeys = function (exportedPublicKey, privateKey) {
    return (exportedPublicKey instanceof CryptoKey
        ? Promise.resolve(exportedPublicKey)
        : subtle$1.importKey("raw", exportedPublicKey, { name: "ECDH", namedCurve: "P-521" }, true, [])).then(function (managerKey) {
        return subtle$1.deriveKey({ name: "ECDH", public: managerKey }, privateKey, { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
    });
};
var importEncryptionKey = function (input) {
    return subtle$1.importKey("raw", input.slice(0, 16), { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
};
var deriveBits = function (exportedPublicKey, privateKey) {
    return (exportedPublicKey instanceof CryptoKey
        ? Promise.resolve(exportedPublicKey)
        : subtle$1.importKey("raw", exportedPublicKey, { name: "ECDH", namedCurve: "P-521" }, true, []))
        .then(function (managerKey) {
        return subtle$1.deriveBits({ name: "ECDH", public: managerKey }, privateKey, 256);
    })
        .then(function (commonBits) { return new Uint8Array(commonBits); });
};
var exchangeKeysAndDecrypt = function (exportedPublicKey, iv, privateKey, cipherText) {
    return exchangeKeys(exportedPublicKey, privateKey)
        .then(function (encryptionKey) {
        return subtle$1.decrypt({
            name: "AES-GCM",
            iv: iv,
        }, encryptionKey, cipherText);
    })
        .then(function (encodedData) { return new Uint8Array(encodedData); });
};
var encrypt = function (encryptionKey, iv, encodedData) {
    return subtle$1
        .encrypt({
        name: "AES-GCM",
        iv: iv,
    }, encryptionKey, encodedData)
        .then(function (cipherText) { return new Uint8Array(cipherText); });
};
var decrypt = function (encryptionKey, iv, cipherText) {
    return subtle$1
        .decrypt({
        name: "AES-GCM",
        iv: iv,
    }, encryptionKey, cipherText)
        .then(function (message) { return new Uint8Array(message); });
};
var exchangeKeysAndEncrypt = function (exportedPublicKey, iv, privateKey, encodedData) {
    return exchangeKeys(exportedPublicKey, privateKey)
        .then(function (encryptionKey) {
        return subtle$1.encrypt({
            name: "AES-GCM",
            iv: iv,
        }, encryptionKey, encodedData);
    })
        .then(function (cipherText) { return new Uint8Array(cipherText); });
};
var resolveSlot = function (slot) {
    return slot instanceof Uint8Array ? getNameFromSeed(slot) : Promise.resolve(slot);
};
var publishAt = function (message, revision, insert) {
};
var writeAt = function (message, _slot, increment) {
    if (increment === void 0) { increment = false; }
    return resolveSlot(_slot).then(function (slot) { return _writeAt(message, slot, increment); });
};
var _writeAt = function (message, slot, increment) {
    if (increment === void 0) { increment = false; }
    var commit = function (revision) { return Name.publish(revision, slot.key); };
    var encodedMessage = encodeBase64(message);
    if (!increment)
        return Name.v0(slot, encodedMessage).then(commit);
    return loadName(slot)
        .then(function (revision) {
        return revision
            ? Name.increment(revision, encodedMessage)
            : Name.v0(slot, encodedMessage);
    })
        .then(commit);
};
var concatBytes = function (input) {
    var result = new Uint8Array(input.reduce(function (acc, i) { return acc + i.length; }, 0));
    for (var seek = 0, i = 0; i < input.length; i += 1) {
        result.set(input[i], seek);
        seek += input[i].length;
    }
    return result;
};
var writeWith = function (wallet, publicKey) {
    return function (message, slot, increment) {
        if (increment === void 0) { increment = true; }
        return subtle$1
            .exportKey("raw", publicKey)
            .then(function (exportedKey) {
            var _message = concatBytes([
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
            .then(function (_a) {
            var _message = _a[0], signature = _a[1];
            return writeAt(concatBytes([getBytes(signature), _message]), slot, increment);
        });
    };
};
var getSlotAt = function (currentSlot, i) {
    if (i === 0)
        return getBytes(currentSlot);
    return getSlotAt(sha256(hexlify(currentSlot)), i - 1);
};
var findSlot = function (slotRoot, left, right) {
    if (left === void 0) { left = 0; }
    if (right === void 0) { right = 15; }
    var middle = left + Math.floor((right - left) / 2);
    var slot = getSlotAt(slotRoot, middle);
    return timeout(500)
        .then(function () { return getNameFromSeed(slot); })
        .then(function (slotName) {
        return loadName(slotName).then(function (revision) {
            console.log(middle, left, right);
            if (middle === right) {
                if (revision === null)
                    return [slotName, slot, middle];
                throw new Error();
            }
            if (revision === null)
                return findSlot(slotRoot, left, middle);
            return findSlot(slotRoot, middle + 1, right);
        });
    });
};
var generateKeyPair = function () {
    return subtle$1.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, [
        "deriveKey",
        "deriveBits",
    ]);
};
var getTimestamp = function () { return Math.floor(new Date().getTime() / 1000); };
var isEmpty = function (data) {
    return dataLength(stripZerosLeft(data)) === 0;
};

var ByteLengthViolation = /** @class */ (function (_super) {
    __extends(ByteLengthViolation, _super);
    function ByteLengthViolation(message) {
        var _this = _super.call(this, message) || this;
        _this.name = "ByteLengthViolation";
        return _this;
    }
    return ByteLengthViolation;
}(Error));
var ec = new TextEncoder();
var dc = new TextDecoder();
var removePadding = function (input) {
    var i = 0;
    while (input[i] === 0 && i++ < input.length)
        ;
    return input.slice(i);
};
function validateByteLength(data, targetLength, minOnly) {
    if (minOnly === void 0) { minOnly = false; }
    if (minOnly && data.byteLength < targetLength)
        return;
    if (data.byteLength !== targetLength)
        throw new ByteLengthViolation("data byte length verification falied. Target byte length: ".concat(targetLength, " Received byte length: ").concat(data.byteLength));
}
function getByteLength(s) {
    return s.type === "boolean"
        ? 1
        : s.type === "nested"
            ? Object.keys(s.schema).reduce(function (sum, k) { return sum + s.schema[k].byteLength; }, 0)
            : s.byteLength
                ? s.byteLength
                : 0;
}
function calculateRepeatingByteLength(schema, data) {
    var dataLength = 0;
    for (var key in schema) {
        var s = schema[key];
        if (s.type === "repeating") {
            var n = toNumber(data.slice(dataLength, dataLength + 4));
            dataLength += 4;
            for (var i = 0; i < n; ++i) {
                dataLength += calculateRepeatingByteLength(s.schema, data.slice(dataLength));
            }
        }
        else
            dataLength += getByteLength(s);
    }
    return dataLength;
}
function applySchema(schema, data) {
    var result = {};
    var needle = 0;
    for (var key in schema) {
        var s = schema[key];
        var byteLength = getByteLength(s);
        var dataEnd = byteLength ? needle + byteLength : data.byteLength;
        var value = data.slice(needle, dataEnd);
        if (s.type === "boolean") {
            result[key] = !!new Uint8Array(value)[0];
        }
        else if (s.type === "string") {
            result[key] = dc.decode(removePadding(new Uint8Array(value)));
        }
        else if (s.type === "number" && s.byteLength) {
            result[key] = toNumber(new Uint8Array(value));
        }
        else if (s.type === "buffer") {
            result[key] = new Uint8Array(value);
        }
        else if (s.type === "hexstring") {
            result[key] = hexlify(new Uint8Array(value));
        }
        else if (s.type === "bignumber") {
            result[key] = BigInt(hexlify(new Uint8Array(value)));
        }
        else if (s.type === "nested") {
            if (!s.schema)
                throw new Error("no schema specified for ".concat(key));
            result[key] = applySchema(s.schema, value);
        }
        else if (s.type === "repeating") {
            result[key] = [];
            if (!s.schema)
                throw new Error("no schema specified for ".concat(key));
            var n = toNumber(value.slice(0, 4));
            needle += 4;
            for (var i_1 = 0; i_1 < n; ++i_1) {
                var dataLength = calculateRepeatingByteLength(s.schema, data.slice(needle));
                result[key].push(applySchema(s.schema, data.slice(needle, needle + dataLength)));
                needle += dataLength;
            }
        }
        needle = dataEnd;
    }
    return result;
}
function buildSchema(schema, _data) {
    var _a;
    var result = new Uint8Array();
    var data = __assign({}, _data);
    var _loop_1 = function (key) {
        if (!(key in data))
            throw new Error("Missing data: ".concat(key));
        var s = schema[key];
        var d = data[key];
        if (s.type === "boolean") {
            result = concatBytes([result, new Uint8Array([d ? 1 : 0])]);
        }
        else if (s.type === "string") {
            var bytes = ec.encode(d);
            result = getBytes(concat([result, zeroPadValue(bytes, (_a = s.byteLength) !== null && _a !== void 0 ? _a : bytes.length)]));
        }
        else if (s.type === "number" && s.byteLength) {
            if (typeof d !== "number") {
                throw new Error("Wrong datatype for ".concat(key, ". Expected number."));
            }
            // not sure why strict type is required
            result = getBytes(concat([result, zeroPadValue(toBeArray(d), s.byteLength)]));
        }
        else if (s.type === "bignumber" && s.byteLength) {
            // not sure why strict type is required
            result = getBytes(concat([result, zeroPadValue(toBeArray(d), s.byteLength)]));
        }
        else if (s.type === "buffer" || s.type === "hexstring") {
            var _d = getBytes(d);
            // arraybuffer type, check for byte length
            if (s.byteLength)
                validateByteLength(_d.buffer, s.byteLength);
            result = concatBytes([result, _d]);
        }
        else if (s.type === "nested") {
            result = concatBytes([
                result,
                buildSchema(s.schema, d),
            ]);
        }
        else if (s.type === "repeating") {
            result = concatBytes([
                result,
                getBytes(zeroPadValue(toBeArray(d.length), 4)),
                concatBytes(d.map(function (_d) {
                    return buildSchema(s.schema, _d);
                })),
            ]);
            // result.bytelength is important here!
        }
        else {
            throw new Error("Unprocessable schema type: ".concat(s.type));
        }
        delete data[key];
    };
    for (var key in schema) {
        _loop_1(key);
    }
    if (Object.keys(data).length) {
        throw new Error("invalid keys supplied to schema: ".concat(Object.keys(data)));
    }
    return result;
}
var messageSchema = {
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

var slotSchema = {
    slotRoot: {
        type: "buffer",
        byteLength: 32,
    },
    publicKey: {
        type: "buffer",
        byteLength: 133,
    },
    publishedAt: {
        type: 'number',
        byteLength: 8,
    },
    data: {
        // arbitrary data that can be added to announcement
        type: 'buffer'
    }
};
var signedSlotSchema = __assign({ signature: {
        type: "hexstring",
        byteLength: 65,
    } }, slotSchema);
var requestSchema = {
    signature: {
        type: "hexstring",
        byteLength: 65,
    },
    from: {
        type: "hexstring",
        byteLength: 20,
    },
    publicKey: {
        type: "buffer",
        byteLength: 133,
    },
    publishedAt: {
        type: 'number',
        byteLength: 8,
    },
    message: {
        type: "buffer",
    },
};

// this is hardcoded into the application.
var REQUEST_INTERVAL = 5 * 1000;
function parseRequest(input) {
    try {
        var req = applySchema(requestSchema, decodeBase64(input));
        if (req.from !==
            verifyMessage(getBytes(concat([
                req.from,
                req.publicKey,
                zeroPadValue(toBeArray(req.publishedAt), 8),
                req.message,
            ])), req.signature).toLowerCase())
            return input;
        return req;
    }
    catch (e) {
        return input;
    }
}
function watchSlot(currentName, i) {
    var _this = this;
    if (i === void 0) { i = 0; }
    if (i === 10)
        return Promise.resolve(null);
    return loadName(currentName).then(function (revision) { return __awaiter(_this, void 0, void 0, function () {
        var request;
        return __generator(this, function (_a) {
            if (revision === null) {
                console.log("empty ".concat(i, " at ").concat(currentName.toString()));
                return [2 /*return*/, timeout(REQUEST_INTERVAL).then(function () {
                        return watchSlot(currentName, i + 1);
                    })];
            }
            request = parseRequest(revision.value);
            // faulty value detected in slot. this is an error.
            if (!request)
                return [2 /*return*/, revision.value];
            return [2 /*return*/, request];
        });
    }); });
}
var EmptyRevisionError = /** @class */ (function (_super) {
    __extends(EmptyRevisionError, _super);
    function EmptyRevisionError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return EmptyRevisionError;
}(Error));
var readWith = function (seed, keyholder) {
    return getNameFromSeed(seed)
        .then(loadName)
        .then(function (revision) {
        if (revision === null)
            throw new EmptyRevisionError();
        var _a = applySchema(requestSchema, decodeBase64(revision.value)); _a.from; _a.signature; var message = _a.message, publicKey = _a.publicKey; _a.publishedAt;
        /*
        if (
          verifyMessage(concatBytes([slotRoot, publicKey]), signature) !==
            from
        )
          throw new Error("malformed application root value");*/
        return keyholder.receive(message, seed, publicKey);
    })
        .catch(function (e) {
        if (e instanceof EmptyRevisionError)
            return null;
        throw e;
    });
};

var KeyHolder = /** @class */ (function () {
    function KeyHolder(privateKey, signingKey) {
        this._signingKey = signingKey;
        this.wallet = isHexString(privateKey)
            ? new Wallet(privateKey)
            : privateKey.length > 100
                ? this.importIdentity(privateKey)
                : HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(privateKey));
    }
    Object.defineProperty(KeyHolder.prototype, "publicKey", {
        get: function () {
            var _a;
            if (!((_a = this._signingKey) === null || _a === void 0 ? void 0 : _a.publicKey) ||
                typeof this._signingKey.publicKey === "string")
                throw new Error("key not present?");
            return this._signingKey.publicKey;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(KeyHolder.prototype, "address", {
        get: function () {
            return this.wallet.address;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(KeyHolder.prototype, "signingKey", {
        get: function () {
            if (!this._signingKey ||
                typeof this._signingKey.privateKey === "string" ||
                typeof this._signingKey.publicKey === "string")
                throw new Error("key not set yet");
            return this._signingKey;
        },
        enumerable: false,
        configurable: true
    });
    KeyHolder.prototype.getContractRunner = function (address, abi, provider) {
        return new Contract(address, abi, new Wallet(this.wallet.privateKey, provider));
    };
    KeyHolder.prototype.parseOrGenerateKey = function () {
        if (!this._signingKey) {
            return generateKeyPair().then(function (_a) {
                var privateKey = _a.privateKey, publicKey = _a.publicKey;
                return [
                    privateKey,
                    publicKey,
                ];
            });
        }
        if (typeof this._signingKey.privateKey === "string") {
            return Promise.all([
                importPrivateKey(this._signingKey.privateKey),
                importPublicKey(this._signingKey.publicKey),
            ]);
        }
        return Promise.resolve([
            this._signingKey.privateKey,
            this._signingKey.publicKey,
        ]);
    };
    KeyHolder.prototype.initialize = function () {
        var _this = this;
        return this.parseOrGenerateKey().then(function (_a) {
            var privateKey = _a[0], publicKey = _a[1];
            _this._signingKey = { privateKey: privateKey, publicKey: publicKey };
        });
    };
    KeyHolder.prototype.writeAt = function (message, slot, increment) {
        var _this = this;
        if (increment === void 0) { increment = true; }
        return resolveSlot(slot).then(function (w3name) {
            return writeWith(_this.wallet, _this.signingKey.publicKey)(message, w3name, increment);
        });
    };
    KeyHolder.prototype.encryptAndWrite = function (message, slot, publicKey, increment) {
        var _this = this;
        return (publicKey
            ? exchangeKeys(publicKey, this.signingKey.privateKey)
            : importEncryptionKey(getBytes(this.wallet.privateKey)))
            .then(function (encryptionKey) {
            return encrypt(encryptionKey, slot.slice(0, 12), message);
        })
            .then(function (cipherText) { return _this.writeAt(new Uint8Array(cipherText), slot); });
    };
    KeyHolder.prototype.signMessage = function (message) {
        return this.wallet.signMessage(message);
    };
    /*
     * requires signature to be in 1st position.
     * */
    KeyHolder.prototype.buildSchemaAndSign = function (schema, data) {
        if (schema.timestamp) {
            data.timestamp = getTimestamp();
        }
        var message = buildSchema(schema, data);
        return this.wallet
            .signMessage(message)
            .then(function (signature) {
            return concatBytes([getBytes(signature), message]);
        });
    };
    KeyHolder.prototype.readAndDecrypt = function (slot) {
        var _this = this;
        return readSeedValue(slot).then(function (slotData) {
            if (!slotData)
                return null;
            slotData.slice(0, 65);
            var _a = applySchema(messageSchema, slotData.slice(65)), from = _a.from, publicKey = _a.publicKey, message = _a.message;
            if (from === _this.wallet.address.toLowerCase())
                return _this.receive(message, slot);
            return _this.receive(message, slot, publicKey);
        });
    };
    KeyHolder.prototype.receive = function (cipherText, slot, publicKey) {
        return (publicKey
            ? exchangeKeys(publicKey, this.signingKey.privateKey)
            : importEncryptionKey(getBytes(this.wallet.privateKey))).then(function (encryptionKey) {
            return decrypt(encryptionKey, slot.slice(0, 12), cipherText);
        });
    };
    KeyHolder.prototype.createSecret = function (data) {
        return exportPrivateKey(this.signingKey.privateKey).then(function (privateKey) {
            return getBytes(sha256(concat([data, new TextEncoder().encode(privateKey)])));
        });
    };
    KeyHolder.prototype.createCommonSecret = function (data, publicKey) {
        return deriveBits(publicKey, this.signingKey.privateKey).then(function (commonBits) { return sha256(concat([data, commonBits])); });
    };
    KeyHolder.prototype.importIdentity = function (identity) {
        var identityBytes = decodeBase64(identity);
        var dc = new TextDecoder();
        this._signingKey = {
            privateKey: dc.decode(identityBytes.slice(32, 410)),
            publicKey: dc.decode(identityBytes.slice(410)),
        };
        return new Wallet(hexlify(identityBytes.slice(0, 32)));
    };
    KeyHolder.prototype.exportIdentity = function () {
        var _this = this;
        return Promise.all([
            exportPublicKey(this.signingKey.publicKey),
            exportPrivateKey(this.signingKey.privateKey),
        ]).then(function (_a) {
            var publicKey = _a[0], privateKey = _a[1];
            var ec = new TextEncoder();
            return encodeBase64(concat([
                _this.wallet.privateKey,
                ec.encode(privateKey),
                ec.encode(publicKey),
            ]));
        });
    };
    return KeyHolder;
}());

var emitPer5Seconds = 0;
var eventTypes = new Map();
setInterval(function () {
    if (emitPer5Seconds > 150) {
        console.log("unaccaptable amount of events in the last 3 seconds: ".concat(emitPer5Seconds));
        for (var _i = 0, _a = Array.from(eventTypes.entries()); _i < _a.length; _i++) {
            var _b = _a[_i], type = _b[0], n = _b[1];
            console.log(type, n);
        }
    }
    eventTypes.clear();
    emitPer5Seconds = 0;
}, 3000);
var EventEmitter = /** @class */ (function () {
    function EventEmitter() {
        this.listeners = {};
    }
    EventEmitter.prototype.emit = function (type, ev) {
        var _this = this;
        if (this.listeners[type])
            this.listeners[type].forEach(function (l) {
                emitPer5Seconds++;
                eventTypes.set(type, (eventTypes.get(type) || 0) + 1);
                // TODO: potentially breaking change!
                // listeners now need to be synchronous and should not return a value, unless they want to unsubscribe
                var result = l(ev);
                if (result && !result.then) {
                    _this.listeners[type].delete(l);
                }
            });
    };
    EventEmitter.prototype.addEventListener = function (type, listener) {
        if (!this.listeners[type]) {
            this.listeners[type] = new Set();
        }
        this.listeners[type].add(listener);
    };
    EventEmitter.prototype.removeEventListener = function (type, listener) {
        this.listeners[type].delete(listener);
    };
    EventEmitter.prototype.removeAllListeners = function () {
        for (var k in this.listeners) {
            this.listeners[k].clear();
        }
    };
    return EventEmitter;
}());

var subtle = globalThis.crypto.subtle;
var Manager = /** @class */ (function (_super) {
    __extends(Manager, _super);
    function Manager(privateKey, signingKey) {
        var _this = _super.call(this) || this;
        _this.processedRequests = 0;
        _this.slotIndex = 0;
        _this._slotRoot = null;
        _this._rootName = null;
        _this.generateSlotData = function (keyholder, slotRoot) {
            return Promise.resolve(new Uint8Array());
        };
        _this.publishSlot = function (encodedSlotContent) {
            // Check if name exists..
            return Name.resolve(_this.rootName)
                .then(function (revision) { return Name.increment(revision, encodedSlotContent); })
                .catch(function (e) {
                if (e.message.startsWith("record not found")) {
                    return Name.v0(_this.rootName, encodedSlotContent);
                }
                throw e;
            })
                .then(function (revision) { return Name.publish(revision, _this.rootName.key); })
                .then(function () { return getNameFromSeed(_this.slotRoot); });
        };
        _this.resetOrContinue = function (request) {
            if (request === null)
                return Promise.resolve(undefined);
            // no need to wait for request procession to be completed before looking for the next slot.
            if (typeof request !== "string") {
                var slot_1 = _this.slotRoot.slice();
                _this.keyholder
                    .receive(request.message, slot_1, request.publicKey)
                    .then(function (message) {
                    // storing processed requests...
                    _this.emit("request", {
                        // then next 32 bytes are response slot
                        message: message.slice(32),
                        request: request,
                        slot: slot_1,
                        keyholder: _this.keyholder,
                        respond: function (response) {
                            return _this.keyholder.encryptAndWrite(response, message.slice(0, 32), request.publicKey);
                        },
                    });
                })
                    .catch(function (e) { return console.error(e); });
            }
            return getNameFromSeed(_this.nextSlot)
                .then(function (nextName) { return watchSlot(nextName); })
                .then(_this.resetOrContinue);
        };
        _this.loop = function () {
            _this.generateSlotContent()
                .then(_this.publishSlot)
                // TODO: there are many safeguards you can apply
                // simplest one:
                // only allow requests from addresses that have assets on chain
                // and rate limit them heavily (max 1 game every 5 minutes)
                // since you control matchmaking you can make these restrictions
                // well, that still won't prevent them from pollution
                // but yes their responses can be simply disregarded.
                .then(watchSlot)
                .then(_this.resetOrContinue)
                .then(_this.loop);
        };
        _this.keyholder = new KeyHolder(privateKey, signingKey);
        _this.root = getBytes(sha256(new TextEncoder().encode(privateKey)));
        return _this;
    }
    Object.defineProperty(Manager.prototype, "slotRoot", {
        get: function () {
            if (!this._slotRoot)
                throw new Error("slot root not set yet");
            return this._slotRoot;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Manager.prototype, "rootName", {
        get: function () {
            if (!this._rootName)
                throw new Error("root not set yet");
            return this._rootName;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Manager.prototype, "nextSlot", {
        get: function () {
            this._slotRoot = getBytes(sha256(hexlify(this.slotRoot)));
            this.processedRequests += 1;
            // we can either do
            // batch processing of requests and use response chain
            // do like we did here, give signatures to party based on response
            return this.slotRoot;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Manager.prototype, "address", {
        get: function () {
            return this.keyholder.address;
        },
        enumerable: false,
        configurable: true
    });
    Manager.prototype.signMessage = function (message) {
        return this.keyholder.signMessage(message);
    };
    Manager.prototype.getContractRunner = function (address, abi, provider) {
        return this.keyholder.getContractRunner(address, abi, provider);
    };
    Manager.prototype.listen = function (onMessage, generateSlotData) {
        var _this = this;
        if (onMessage)
            this.addEventListener("request", onMessage);
        if (generateSlotData)
            this.generateSlotData = generateSlotData;
        return this.keyholder
            .initialize()
            .then(function () { return getNameFromSeed(_this.root); })
            .then(function (rootName) {
            _this._rootName = rootName;
            console.log("| ----------- ---------- APPLICATION ROOT ---------- ----------- |\n| ".concat(_this._rootName.toString(), " |\n| ----------- ---------- ---------------- ---------- ----------- |\n"));
        })
            .then(function () {
            _this.loop();
        });
    };
    Manager.prototype.generateSlotRoot = function () {
        this.processedRequests = 0;
        this._slotRoot = randomBytes(32);
    };
    Manager.prototype.generateSlotContent = function () {
        var _this = this;
        this.generateSlotRoot();
        return Promise.all([
            subtle.exportKey("raw", this.keyholder.publicKey),
            this.generateSlotData(this.keyholder, this.slotRoot),
        ]).then(function (_a) {
            var exportedKey = _a[0], data = _a[1];
            var slotContent = buildSchema(slotSchema, {
                slotRoot: _this.slotRoot,
                publicKey: new Uint8Array(exportedKey),
                publishedAt: Math.round(new Date().getTime() / 1000),
                data: data,
                // should also reveal how many managers are watching the slot
                // more managers
                //  make binary search much faster
                //  less collision
                //  more frequent request processing
            });
            return Promise.all([
                Promise.resolve(slotContent),
                _this.signMessage(slotContent),
            ]).then(function (_a) {
                var slotContent = _a[0], signature = _a[1];
                return encodeBase64(concat([signature, slotContent]));
            });
        });
    };
    Manager.prototype.createSecret = function (data) {
        return this.keyholder.createSecret(data);
    };
    Manager.prototype.respondAt = function (slot, publicKey, message, increment) {
        if (increment === void 0) { increment = true; }
        return this.keyholder.encryptAndWrite(message, slot, publicKey, increment);
    };
    return Manager;
}(EventEmitter));

var readRoot = function (applicationRoot) {
    return loadName(Name.parse(applicationRoot)).then(function (revision) {
        if (revision === null)
            throw new Error("application root not found");
        return applySchema(signedSlotSchema, decodeBase64(revision.value));
    });
};
var readLastValue = function (applicationRoot, keyholder) {
    return loadName(Name.parse(applicationRoot)).then(function (revision) {
        if (revision === null)
            throw new Error("application root not found");
        var _a = applySchema(signedSlotSchema, decodeBase64(revision.value)); _a.signature; var slotRoot = _a.slotRoot; _a.publicKey;
        return findSlot(slotRoot)
            .then(function (_a) {
            _a[0]; _a[1]; var c = _a[2];
            return getNameFromSeed(getSlotAt(slotRoot, c - 1));
        })
            .then(loadName)
            .then(function (revision) {
            if (revision === null)
                return null;
            var _a = applySchema(requestSchema, decodeBase64(revision.value)), signature = _a.signature, from = _a.from, message = _a.message, publicKey = _a.publicKey;
            return {
                from: from,
                signature: signature,
                message: message,
                publicKey: publicKey,
            };
        });
    });
};
var sendRequest = function (applicationRoot, keyholder, message, expectResponse, identity) {
    if (expectResponse === void 0) { expectResponse = false; }
    var responseSlot = randomBytes(32);
    return loadName(Name.parse(applicationRoot)).then(function (revision) {
        if (revision === null)
            throw new Error("application root not found");
        var _a = applySchema(signedSlotSchema, decodeBase64(revision.value)), signature = _a.signature, slotRoot = _a.slotRoot, publicKey = _a.publicKey;
        if (identity &&
            verifyMessage(concatBytes([slotRoot, publicKey]), signature) !== identity)
            throw new Error("malformed application root value");
        return findSlot(slotRoot)
            .then(function (_a) {
            _a[0]; var slot = _a[1];
            return keyholder.encryptAndWrite(concatBytes([responseSlot, message]), slot, publicKey);
        })
            .then(function (result) {
            if (!expectResponse)
                return Promise.resolve(null);
            return getNameFromSeed(responseSlot)
                .then(function (responseName) { return watchSlot(responseName); })
                .then(function (value) {
                if (value === null || typeof value === "string")
                    return null;
                return keyholder.receive(value.message, responseSlot, value.publicKey);
            });
        });
    });
};

export { ByteLengthViolation, EventEmitter, KeyHolder, Manager as Service, _writeAt, applySchema, buildSchema, bytesToName, concatBytes, dc, decrypt, deriveBits, ec, encrypt, exchangeKeys, exchangeKeysAndDecrypt, exchangeKeysAndEncrypt, exportPrivateKey, exportPublicKey, findSlot, generateKeyPair, getNameAsBytes, getNameFromSeed, getSlotAt, getTimestamp, importEncryptionKey, importPrivateKey, importPublicKey, isEmpty, loadName, messageSchema, parseNameFromBytes, publishAt, readLastValue, readRoot, readSeedValue, readValueAt, readValueAtAddress, readWith, resolveSlot, sendRequest, timeout, validateByteLength, watchSlot, writeAt, writeWith };
//# sourceMappingURL=index.esm.js.map
