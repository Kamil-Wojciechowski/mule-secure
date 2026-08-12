import { createMuleCrypto } from './crypto-core.js';
import { applyOverFile } from './file-core.js';
import { Blowfish } from './vendor/blowfish.mjs';

const MuleCrypto = createMuleCrypto(window.forge, Blowfish);


const SELF_TEST_VECTORS = [
  { algo: 'AES', mode: 'CBC', key: '0123456789ABCDEF', value: 'hello', expect: 'a7T7Pnehm1REEcuTceQgJw==' },
  { algo: 'AES', mode: 'CFB', key: '0123456789ABCDEF', value: 'hello', expect: '5eYxYJDTsd6O9YBJn88qgw==' },
  { algo: 'DES', mode: 'CBC', key: '01234567', value: 'hello', expect: 'qWuit2s3cGA=' },
  { algo: 'DESede', mode: 'CBC', key: 'AAAAAAAABBBBBBBBCCCCCCCC', value: 'hello', expect: 'HGCeCMjIrd8=' },
  { algo: 'Blowfish', mode: 'CBC', key: '0123456789ABCDEF', value: 'hello', expect: '/E5Siiqsq6s=' },
  { algo: 'RC2', mode: 'CBC', key: '0123456789ABCDEF', value: 'hello', expect: 'opJTi4znG1w=' },
];

const FILE_SELF_TEST = {
  input: 'a=hello\nb="hi"\n# comment\nc=world\n',
  format: 'properties',
  expect: 'a=![a7T7Pnehm1REEcuTceQgJw==]\nb="![If8MnEuuiR3pD4EUdumQgA==]"\n# comment\nc=![7F4aFXkp1+GnxhnjAVqJ4w==]\n',
};

function runSelfTest() {
  for (const v of SELF_TEST_VECTORS) {
    const got = MuleCrypto.encryptString(v.algo, v.mode, v.key, v.value, false);
    if (got !== v.expect) {
      throw new Error(`Self-test failed for ${v.algo}/${v.mode}: expected ${v.expect}, got ${got}`);
    }
    const back = MuleCrypto.decryptString(v.algo, v.mode, v.key, got, false);
    if (back !== v.value) {
      throw new Error(`Self-test round-trip failed for ${v.algo}/${v.mode}`);
    }
  }

  const fileGot = applyOverFile(
    MuleCrypto, 'encrypt', 'AES', 'CBC', '0123456789ABCDEF', false,
    FILE_SELF_TEST.input, FILE_SELF_TEST.format
  );
  if (fileGot !== FILE_SELF_TEST.expect) {
    throw new Error(`File-mode self-test failed: expected ${JSON.stringify(FILE_SELF_TEST.expect)}, got ${JSON.stringify(fileGot)}`);
  }
  const fileBack = applyOverFile(
    MuleCrypto, 'decrypt', 'AES', 'CBC', '0123456789ABCDEF', false,
    fileGot, FILE_SELF_TEST.format
  );
  const expectedBack = 'a=hello\nb="hi"\n# comment\nc=world\n';
  if (fileBack !== expectedBack) {
    throw new Error(`File-mode self-test round-trip failed: got ${JSON.stringify(fileBack)}`);
  }
}

const KEY_SIZE_HINTS = {
  AES: 'AES requires a key of exactly 16, 24, or 32 bytes.',
  DES: 'DES requires a key of exactly 8 bytes.',
  DESede: 'DESede (3DES) requires a key of exactly 24 bytes.',
  Blowfish: 'Blowfish accepts a key of 1-56 bytes.',
  RC2: 'RC2 accepts a key of 1-128 bytes.',
};

const els = {
  operation: document.querySelectorAll('input[name="operation"]'),
  inputType: document.querySelectorAll('input[name="inputType"]'),
  algorithm: document.getElementById('algorithm'),
  mode: document.getElementById('mode'),
  key: document.getElementById('key'),
  toggleKey: document.getElementById('toggleKey'),
  keyHint: document.getElementById('keyHint'),
  value: document.getElementById('value'),
  valueLabel: document.getElementById('valueLabel'),
  useRandomIv: document.getElementById('useRandomIv'),
  wrapOutput: document.getElementById('wrapOutput'),
  wrapOutputRow: document.getElementById('wrapOutputRow'),
  fileFormatRow: document.getElementById('fileFormatRow'),
  fileFormat: document.getElementById('fileFormat'),
  fileLoader: document.getElementById('fileLoader'),
  run: document.getElementById('run'),
  output: document.getElementById('output'),
  copy: document.getElementById('copy'),
  download: document.getElementById('download'),
  error: document.getElementById('error'),
  form: document.getElementById('form'),
  bootError: document.getElementById('bootError'),
};

let loadedFileName = null;

function currentOperation() {
  for (const r of els.operation) if (r.checked) return r.value;
  return 'encrypt';
}

function currentInputType() {
  for (const r of els.inputType) if (r.checked) return r.value;
  return 'string';
}

function updateHintsAndVisibility() {
  const algo = els.algorithm.value;
  els.keyHint.textContent = KEY_SIZE_HINTS[algo] || '';

  const isEcb = els.mode.value === 'ECB';
  els.useRandomIv.disabled = isEcb;
  if (isEcb) els.useRandomIv.checked = false;

  const op = currentOperation();
  const inputType = currentInputType();
  const isFile = inputType === 'file';

  els.form.classList.toggle('file-mode', isFile);
  els.fileFormatRow.style.display = isFile ? '' : 'none';
  els.wrapOutputRow.style.display = !isFile && op === 'encrypt' ? '' : 'none';
  els.download.style.display = isFile ? '' : 'none';

  if (isFile) {
    els.valueLabel.textContent = op === 'encrypt' ? 'File content to encrypt' : 'File content to decrypt';
  } else {
    els.valueLabel.textContent = op === 'encrypt' ? 'Value to encrypt' : 'Base64 value to decrypt';
  }
  els.run.textContent = op === 'encrypt' ? 'Encrypt' : 'Decrypt';
}

for (const r of els.operation) r.addEventListener('change', updateHintsAndVisibility);
for (const r of els.inputType) r.addEventListener('change', updateHintsAndVisibility);
els.algorithm.addEventListener('change', updateHintsAndVisibility);
els.mode.addEventListener('change', updateHintsAndVisibility);

els.fileLoader.addEventListener('change', async () => {
  const file = els.fileLoader.files[0];
  if (!file) return;
  loadedFileName = file.name;
  els.value.value = await file.text();
  if (/\.ya?ml$/i.test(file.name)) {
    els.fileFormat.value = 'yaml';
  } else if (/\.properties$/i.test(file.name)) {
    els.fileFormat.value = 'properties';
  }
});

function downloadFilename() {
  const op = currentOperation();
  const ext = els.fileFormat.value === 'yaml' ? 'yaml' : 'properties';
  if (loadedFileName) {
    const prefix = op === 'encrypt' ? 'encrypted-' : 'decrypted-';
    return prefix + loadedFileName;
  }
  return `${op === 'encrypt' ? 'encrypted' : 'decrypted'}.${ext}`;
}

els.download.addEventListener('click', () => {
  if (!els.output.value) return;
  const blob = new Blob([els.output.value], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = downloadFilename();
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

els.toggleKey.addEventListener('click', () => {
  const isPassword = els.key.type === 'password';
  els.key.type = isPassword ? 'text' : 'password';
  els.toggleKey.textContent = isPassword ? 'Hide' : 'Show';
});

els.copy.addEventListener('click', async () => {
  if (!els.output.value) return;
  await navigator.clipboard.writeText(els.output.value);
  els.copy.textContent = 'Copied!';
  setTimeout(() => { els.copy.textContent = 'Copy'; }, 1200);
});

const WRAP_RE = /^!\[([\s\S]*)\]$/;
const MAX_ERROR_LINES = 8;

function formatFileError(err) {
  const lines = err.message.split('\n');
  if (lines.length <= MAX_ERROR_LINES) return err.message;
  const shown = lines.slice(0, MAX_ERROR_LINES);
  return shown.join('\n') + `\n...and ${lines.length - MAX_ERROR_LINES} more line(s) with the same problem.`;
}

els.form.addEventListener('submit', (e) => {
  e.preventDefault();
  els.error.textContent = '';
  els.output.value = '';

  const algo = els.algorithm.value;
  const mode = els.mode.value;
  const key = els.key.value;
  const useRandomIv = els.useRandomIv.checked;
  const op = currentOperation();
  const inputType = currentInputType();
  let value = els.value.value;

  if (!key) {
    els.error.textContent = 'Key is required.';
    return;
  }
  if (!value) {
    els.error.textContent = inputType === 'file' ? 'File content is required.' : 'Value is required.';
    return;
  }

  if (inputType === 'file') {
    try {
      const result = applyOverFile(MuleCrypto, op, algo, mode, key, useRandomIv, value, els.fileFormat.value);
      els.output.value = result;
    } catch (err) {
      els.error.textContent = formatFileError(err);
      if (err.partialOutput) els.output.value = err.partialOutput;
    }
    return;
  }

  try {
    if (op === 'encrypt') {
      const result = MuleCrypto.encryptString(algo, mode, key, value, useRandomIv);
      els.output.value = els.wrapOutput.checked ? `![${result}]` : result;
    } else {
      const m = value.trim().match(WRAP_RE);
      if (m) value = m[1];
      const result = MuleCrypto.decryptString(algo, mode, key, value, useRandomIv);
      els.output.value = result;
    }
  } catch (err) {
    els.error.textContent = err.message || String(err);
  }
});

try {
  runSelfTest();
  updateHintsAndVisibility();
} catch (err) {
  els.bootError.textContent =
    'Startup self-test failed, so the form has been disabled for safety: ' + err.message;
  els.bootError.style.display = '';
  els.form.style.display = 'none';
}
