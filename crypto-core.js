// Pure-logic port of MuleSoft's secure-properties-tool (com.mulesoft.tools.SecurePropertiesTool).
// Reproduces its exact byte-level behavior: raw (unhashed) key bytes, PKCS5/PKCS7 padding
// applied even in CFB/OFB "stream" modes, IV = first blockSize bytes of the key unless a
// random IV is requested (in which case it is prepended to the ciphertext), Base64 output.
//
// Dependencies are injected so this file runs unmodified in Node (tests) and the browser:
//   createMuleCrypto(forgeInstance, BlowfishCtor)

export function createMuleCrypto(forge, Blowfish) {

  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: false });

  function bytesToForge(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }
  function forgeToBytes(str) {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
    return out;
  }
  function b64encode(bytes) {
    return btoa(bytesToForge(bytes));
  }
  function b64decode(str) {
    return forgeToBytes(atob(str));
  }

  function pkcs7pad(bytes, blockSize) {
    const padLen = blockSize - (bytes.length % blockSize);
    const out = new Uint8Array(bytes.length + padLen);
    out.set(bytes);
    out.fill(padLen, bytes.length);
    return out;
  }
  function pkcs7unpad(bytes, blockSize) {
    if (bytes.length === 0 || bytes.length % blockSize !== 0) {
      throw new Error('Invalid padded data length');
    }
    const padLen = bytes[bytes.length - 1];
    if (padLen < 1 || padLen > blockSize) {
      throw new Error('Invalid padding');
    }
    for (let i = bytes.length - padLen; i < bytes.length; i++) {
      if (bytes[i] !== padLen) throw new Error('Invalid padding');
    }
    return bytes.slice(0, bytes.length - padLen);
  }

  // ---- raw single-block ciphers -------------------------------------------------
  // Each returns { blockSize, encryptBlock(bytes)->bytes, decryptBlock(bytes)->bytes }
  // operating on exactly one block, with NO padding/chaining/IV applied.

  function forgeRawBlockCipher(forgeAlgoName, blockSize, keyBytes) {
    const noPad = function() { return true; };
    return {
      blockSize,
      encryptBlock(block) {
        const cipher = forge.cipher.createCipher(forgeAlgoName + '-ECB', bytesToForge(keyBytes));
        cipher.start();
        cipher.update(forge.util.createBuffer(bytesToForge(block)));
        if (!cipher.finish(noPad)) throw new Error('block encrypt failed');
        return forgeToBytes(cipher.output.getBytes());
      },
      decryptBlock(block) {
        const decipher = forge.cipher.createDecipher(forgeAlgoName + '-ECB', bytesToForge(keyBytes));
        decipher.start();
        decipher.update(forge.util.createBuffer(bytesToForge(block)));
        if (!decipher.finish(noPad)) throw new Error('block decrypt failed');
        return forgeToBytes(decipher.output.getBytes());
      },
    };
  }

  function rc2RawBlockCipher(keyBytes) {
    const noPad = function() { return true; };
    const effBits = keyBytes.length * 8;
    return {
      blockSize: 8,
      encryptBlock(block) {
        const cipher = forge.rc2.createEncryptionCipher(bytesToForge(keyBytes), effBits);
        cipher.start(null);
        cipher.update(forge.util.createBuffer(bytesToForge(block)));
        if (!cipher.finish(noPad)) throw new Error('rc2 block encrypt failed');
        return forgeToBytes(cipher.output.getBytes());
      },
      decryptBlock(block) {
        const decipher = forge.rc2.createDecryptionCipher(bytesToForge(keyBytes), effBits);
        decipher.start(null);
        decipher.update(forge.util.createBuffer(bytesToForge(block)));
        if (!decipher.finish(noPad)) throw new Error('rc2 block decrypt failed');
        return forgeToBytes(decipher.output.getBytes());
      },
    };
  }

  function blowfishRawBlockCipher(keyBytes) {
    if (keyBytes.length < 1 || keyBytes.length > 56) {
      throw new Error('Blowfish key must be 1-56 bytes');
    }
    const bf = new Blowfish(keyBytes, Blowfish.MODE.ECB);
    function wordsFromBlock(block) {
      return [
        ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) >>> 0,
        ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) >>> 0,
      ];
    }
    function blockFromWords(l, r) {
      return new Uint8Array([
        (l >>> 24) & 255, (l >>> 16) & 255, (l >>> 8) & 255, l & 255,
        (r >>> 24) & 255, (r >>> 16) & 255, (r >>> 8) & 255, r & 255,
      ]);
    }
    return {
      blockSize: 8,
      encryptBlock(block) {
        const [l, r] = wordsFromBlock(block);
        const [el, er] = bf._encryptBlock(l, r);
        return blockFromWords(el, er);
      },
      decryptBlock(block) {
        const [l, r] = wordsFromBlock(block);
        const [dl, dr] = bf._decryptBlock(l, r);
        return blockFromWords(dl, dr);
      },
    };
  }

  const ALGORITHMS = {
    AES: { minKeySize: 16, validKeySizes: [16, 24, 32], make: (k) => forgeRawBlockCipher('AES', 16, k) },
    DES: { minKeySize: 8, validKeySizes: [8], make: (k) => forgeRawBlockCipher('DES', 8, k) },
    DESede: { minKeySize: 16, validKeySizes: [24], make: (k) => forgeRawBlockCipher('3DES', 8, k) },
    Blowfish: { minKeySize: 1, validKeySizes: null, minBytes: 1, maxBytes: 56, make: (k) => blowfishRawBlockCipher(k) },
    RC2: { minKeySize: 1, validKeySizes: null, minBytes: 1, maxBytes: 128, make: (k) => rc2RawBlockCipher(k) },
  };

  function validateKeySize(algorithm, keyBytes) {
    const spec = ALGORITHMS[algorithm];
    if (!spec) throw new Error(`Unsupported algorithm: ${algorithm}`);
    if (spec.validKeySizes) {
      if (!spec.validKeySizes.includes(keyBytes.length)) {
        const sizes = spec.validKeySizes;
        const expected = sizes.length === 1
          ? `${sizes[0]}`
          : `${sizes.slice(0, -1).join(', ')} or ${sizes[sizes.length - 1]}`;
        throw new Error(
          `Invalid key length for ${algorithm}: ${keyBytes.length} bytes (expected ${expected})`
        );
      }
    } else if (keyBytes.length < spec.minBytes || keyBytes.length > spec.maxBytes) {
      throw new Error(
        `Invalid key length for ${algorithm}: ${keyBytes.length} bytes ` +
        `(expected ${spec.minBytes}-${spec.maxBytes})`
      );
    }
  }

  // ---- generic mode + padding wrapper, matching javax.crypto/SunJCE semantics ----

  function xorBlock(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function deriveDefaultIv(keyBytes, blockSize) {
    const iv = new Uint8Array(blockSize);
    iv.set(keyBytes.slice(0, Math.min(blockSize, keyBytes.length)));
    return iv;
  }

  function modeEncrypt(mode, block, plainPadded) {
    const { blockSize, encryptBlock, decryptBlock } = block;
    const out = new Uint8Array(plainPadded.length);
    let feedback = block.iv;
    for (let off = 0; off < plainPadded.length; off += blockSize) {
      const pBlock = plainPadded.subarray(off, off + blockSize);
      let cBlock;
      if (mode === 'ECB') {
        cBlock = encryptBlock(pBlock);
      } else if (mode === 'CBC') {
        cBlock = encryptBlock(xorBlock(pBlock, feedback));
        feedback = cBlock;
      } else if (mode === 'CFB') {
        const keystream = encryptBlock(feedback);
        cBlock = xorBlock(pBlock, keystream);
        feedback = cBlock;
      } else if (mode === 'OFB') {
        feedback = encryptBlock(feedback);
        cBlock = xorBlock(pBlock, feedback);
      } else {
        throw new Error(`Unsupported mode: ${mode}`);
      }
      out.set(cBlock, off);
    }
    return out;
  }

  function modeDecrypt(mode, block, cipherBytes) {
    const { blockSize, encryptBlock, decryptBlock } = block;
    if (cipherBytes.length === 0 || cipherBytes.length % blockSize !== 0) {
      throw new Error('Ciphertext length is not a multiple of the block size');
    }
    const out = new Uint8Array(cipherBytes.length);
    let feedback = block.iv;
    for (let off = 0; off < cipherBytes.length; off += blockSize) {
      const cBlock = cipherBytes.subarray(off, off + blockSize);
      let pBlock;
      if (mode === 'ECB') {
        pBlock = decryptBlock(cBlock);
      } else if (mode === 'CBC') {
        pBlock = xorBlock(decryptBlock(cBlock), feedback);
        feedback = cBlock;
      } else if (mode === 'CFB') {
        const keystream = encryptBlock(feedback);
        pBlock = xorBlock(cBlock, keystream);
        feedback = cBlock;
      } else if (mode === 'OFB') {
        feedback = encryptBlock(feedback);
        pBlock = xorBlock(cBlock, feedback);
      } else {
        throw new Error(`Unsupported mode: ${mode}`);
      }
      out.set(pBlock, off);
    }
    return out;
  }

  function encryptBytes(algorithm, mode, keyBytes, plainBytes, useRandomIV) {
    validateKeySize(algorithm, keyBytes);
    const cipher = ALGORITHMS[algorithm].make(keyBytes);
    const blockSize = cipher.blockSize;
    const padded = pkcs7pad(plainBytes, blockSize);

    if (mode === 'ECB') {
      cipher.iv = null;
      return modeEncrypt(mode, cipher, padded);
    }

    let iv;
    if (useRandomIV) {
      iv = crypto.getRandomValues(new Uint8Array(blockSize));
    } else {
      iv = deriveDefaultIv(keyBytes, blockSize);
    }
    cipher.iv = iv;
    const ct = modeEncrypt(mode, cipher, padded);
    if (useRandomIV) {
      const out = new Uint8Array(iv.length + ct.length);
      out.set(iv, 0);
      out.set(ct, iv.length);
      return out;
    }
    return ct;
  }

  function decryptBytes(algorithm, mode, keyBytes, cipherBytes, useRandomIV) {
    validateKeySize(algorithm, keyBytes);
    const cipher = ALGORITHMS[algorithm].make(keyBytes);
    const blockSize = cipher.blockSize;

    if (mode === 'ECB') {
      cipher.iv = null;
      return pkcs7unpad(modeDecrypt(mode, cipher, cipherBytes), blockSize);
    }

    let iv, ct;
    if (useRandomIV) {
      iv = cipherBytes.slice(0, blockSize);
      ct = cipherBytes.slice(blockSize);
    } else {
      iv = deriveDefaultIv(keyBytes, blockSize);
      ct = cipherBytes;
    }
    cipher.iv = iv;
    return pkcs7unpad(modeDecrypt(mode, cipher, ct), blockSize);
  }

  // ---- Java-literal unescape, matching Apache Commons StringEscapeUtils.unescapeJava --
  function unescapeJava(value) {
    let out = '';
    for (let i = 0; i < value.length; i++) {
      const c = value[i];
      if (c !== '\\' || i === value.length - 1) {
        out += c;
        continue;
      }
      const next = value[i + 1];
      switch (next) {
        case 'n': out += '\n'; i++; break;
        case 't': out += '\t'; i++; break;
        case 'r': out += '\r'; i++; break;
        case 'b': out += '\b'; i++; break;
        case 'f': out += '\f'; i++; break;
        case '\\': out += '\\'; i++; break;
        case '\'': out += '\''; i++; break;
        case '"': out += '"'; i++; break;
        case 'u': {
          const hex = value.slice(i + 2, i + 6);
          if (/^[0-9a-fA-F]{4}$/.test(hex)) {
            out += String.fromCharCode(parseInt(hex, 16));
            i += 5;
          } else {
            out += c;
          }
          break;
        }
        default:
          out += c;
      }
    }
    return out;
  }

  // ---- top level, matching SecurePropertiesTool.applyOverString ----
  function encryptString(algorithm, mode, key, value, useRandomIV) {
    const keyBytes = te.encode(key);
    const unescaped = unescapeJava(value);
    const plainBytes = te.encode(unescaped);
    const cipherBytes = encryptBytes(algorithm, mode, keyBytes, plainBytes, !!useRandomIV);
    return b64encode(cipherBytes);
  }

  function decryptString(algorithm, mode, key, base64Value, useRandomIV) {
    const keyBytes = te.encode(key);
    const cipherBytes = b64decode(base64Value);
    const plainBytes = decryptBytes(algorithm, mode, keyBytes, cipherBytes, !!useRandomIV);
    return td.decode(plainBytes);
  }

  return {
    ALGORITHMS,
    encryptString,
    decryptString,
    _internal: { encryptBytes, decryptBytes, unescapeJava, validateKeySize },
  };
}
