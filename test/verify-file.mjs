// Regression test for file mode ("file encrypt"/"file decrypt"), replaying
// fixtures captured from the real secure-properties-tool-j17.jar
// (`java -cp secure-properties-tool-j17.jar com.mulesoft.tools.SecurePropertiesTool
// file encrypt|decrypt AES CBC <key> <in> <out>`) against file-core.js.
//
// Run with: npm install && npm test

import { createMuleCrypto } from '../crypto-core.js';
import { applyOverFile } from '../file-core.js';
import { Blowfish } from '../vendor/blowfish.mjs';
import forge from 'node-forge';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fx = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

const MuleCrypto = createMuleCrypto(forge, Blowfish);
const KEY = '0123456789ABCDEF';

let failures = 0;
function check(name, got, expectFixture) {
  const expect = fx(expectFixture);
  if (got !== expect) {
    failures++;
    console.error(`FAIL ${name}`);
    console.error('  expected:', JSON.stringify(expect));
    console.error('  got:     ', JSON.stringify(got));
  }
}

check(
  'properties encrypt',
  applyOverFile(MuleCrypto, 'encrypt', 'AES', 'CBC', KEY, false, fx('basic.properties'), 'properties'),
  'basic.enc.properties'
);
check(
  'yaml encrypt',
  applyOverFile(MuleCrypto, 'encrypt', 'AES', 'CBC', KEY, false, fx('basic.yaml'), 'yaml'),
  'basic.enc.yaml'
);
check(
  'properties decrypt (from real jar output)',
  applyOverFile(MuleCrypto, 'decrypt', 'AES', 'CBC', KEY, false, fx('basic.enc.properties'), 'properties'),
  'basic.dec.properties'
);
check(
  'yaml decrypt (from real jar output)',
  applyOverFile(MuleCrypto, 'decrypt', 'AES', 'CBC', KEY, false, fx('basic.enc.yaml'), 'yaml'),
  'basic.dec.yaml'
);
check(
  'edge-case encrypt (empty-quoted value, already-wrapped value)',
  applyOverFile(MuleCrypto, 'encrypt', 'AES', 'CBC', KEY, false, fx('edge.properties'), 'properties'),
  'edge.enc.properties'
);
check(
  'mixed encrypted/plain decrypt (plain values pass through untouched)',
  applyOverFile(MuleCrypto, 'decrypt', 'AES', 'CBC', KEY, false, fx('edge.properties'), 'properties'),
  'edge.dec.properties'
);
check(
  'CRLF input normalizes to LF output',
  applyOverFile(MuleCrypto, 'encrypt', 'AES', 'CBC', KEY, false, fx('crlf.properties'), 'properties'),
  'crlf.enc.properties'
);
check(
  'random-IV file decrypt (from real jar output)',
  applyOverFile(MuleCrypto, 'decrypt', 'AES', 'CBC', KEY, true, fx('basic.enc.riv.properties'), 'properties'),
  'basic.dec.riv.properties'
);

// self round trip with random IV
const selfEnc = applyOverFile(MuleCrypto, 'encrypt', 'AES', 'CBC', KEY, true, fx('basic.properties'), 'properties');
const selfDec = applyOverFile(MuleCrypto, 'decrypt', 'AES', 'CBC', KEY, true, selfEnc, 'properties');
check('random-IV self round-trip', selfDec, 'basic.dec.properties');

if (failures === 0) {
  console.log('OK: file-mode fixtures all matched.');
  process.exit(0);
} else {
  console.error(`FAILED: ${failures} mismatches.`);
  process.exit(1);
}
