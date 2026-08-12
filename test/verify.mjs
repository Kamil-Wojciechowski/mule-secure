// Regression test: replays reference vectors captured from the real
// secure-properties-tool-j17.jar (`java -cp secure-properties-tool-j17.jar
// com.mulesoft.tools.SecurePropertiesTool string encrypt <algo> <mode> <key> <value>`)
// against crypto-core.js, for both the encrypt and decrypt direction.
//
// Run with: npm install && npm test

import { createMuleCrypto } from '../crypto-core.js';
import { Blowfish } from '../vendor/blowfish.mjs';
import forge from 'node-forge';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8'));

const MuleCrypto = createMuleCrypto(forge, Blowfish);

let failures = 0;

for (const v of vectors) {
  const gotEncrypt = MuleCrypto.encryptString(v.algo, v.mode, v.key, v.value, false);
  if (gotEncrypt !== v.expect) {
    failures++;
    console.error(`ENCRYPT MISMATCH ${v.algo}/${v.mode} key=${v.key} value=${JSON.stringify(v.value)}`);
    console.error(`  expected: ${v.expect}`);
    console.error(`  got:      ${gotEncrypt}`);
  }

  const gotDecrypt = MuleCrypto.decryptString(v.algo, v.mode, v.key, v.expect, false);
  if (gotDecrypt !== v.value) {
    failures++;
    console.error(`DECRYPT MISMATCH ${v.algo}/${v.mode} key=${v.key}`);
    console.error(`  expected: ${JSON.stringify(v.value)}`);
    console.error(`  got:      ${JSON.stringify(gotDecrypt)}`);
  }
}

// Random-IV round trip (ciphertext is non-deterministic, so we can only
// verify that JS-encrypted output decrypts back to the original with JS).
for (const v of vectors.filter(v => v.mode !== 'ECB').slice(0, 20)) {
  const ct = MuleCrypto.encryptString(v.algo, v.mode, v.key, v.value, true);
  const back = MuleCrypto.decryptString(v.algo, v.mode, v.key, ct, true);
  if (back !== v.value) {
    failures++;
    console.error(`RANDOM-IV ROUND-TRIP MISMATCH ${v.algo}/${v.mode}`);
  }
}

if (failures === 0) {
  console.log(`OK: ${vectors.length} vectors, encrypt + decrypt + random-IV round-trip all matched.`);
  process.exit(0);
} else {
  console.error(`FAILED: ${failures} mismatches.`);
  process.exit(1);
}
