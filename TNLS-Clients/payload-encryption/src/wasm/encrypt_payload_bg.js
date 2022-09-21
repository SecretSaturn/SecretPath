import * as wasm from "./encrypt_payload_bg.wasm";

let cachedUint8Memory0 = new Uint8Array();

function getUint8Memory0() {
  if (cachedUint8Memory0.byteLength === 0) {
    cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8Memory0;
}

let WASM_VECTOR_LEN = 0;

function passArray8ToWasm0(arg, malloc) {
  const ptr = malloc(arg.length * 1);
  getUint8Memory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}

let cachedInt32Memory0 = new Int32Array();

function getInt32Memory0() {
  if (cachedInt32Memory0.byteLength === 0) {
    cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
  }
  return cachedInt32Memory0;
}

function getArrayU8FromWasm0(ptr, len) {
  return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
 * @param {Uint8Array} gateway_public_key
 * @param {Uint8Array} user_private_key
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} nonce
 * @returns {Uint8Array}
 */
export function encrypt_payload(
  gateway_public_key,
  user_private_key,
  plaintext,
  nonce
) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passArray8ToWasm0(gateway_public_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(user_private_key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    wasm.encrypt_payload(
      retptr,
      ptr0,
      len0,
      ptr1,
      len1,
      ptr2,
      len2,
      ptr3,
      len3
    );
    const r0 = getInt32Memory0()[retptr / 4 + 0];
    const r1 = getInt32Memory0()[retptr / 4 + 1];
    const v4 = getArrayU8FromWasm0(r0, r1).slice();
    wasm.__wbindgen_free(r0, r1 * 1);
    return v4;
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
}
