// Port of SecurePropertiesTool's "file" mode (applyOverFile / processFileLine /
// removeComment / getComment). Operates purely on the already-validated string
// encrypt/decrypt functions from crypto-core.js - no crypto logic lives here,
// just the line/quote/comment parsing that decides *which* substring of each
// line gets encrypted or decrypted.

const ESCAPED_DOUBLE_QUOTE = '\\"';
const WRAP_RE = /!\[(.*)\]/;

// Mirrors Java's String.split(regex) with the default limit (0): every
// trailing empty string is discarded, but empty strings in the middle stay.
function javaSplit(str, sep) {
  if (str.length === 0) return [''];
  const parts = str.split(sep);
  let end = parts.length;
  while (end > 0 && parts[end - 1] === '') end--;
  return parts.slice(0, end);
}

// Mirrors SecurePropertiesTool.removeComment: returns the line up to (not
// including) a '#' that starts a comment, where a '#' inside a quoted
// section (opened by an unescaped ") doesn't count as a comment start.
function removeComment(line) {
  let result = '';
  let opened = false;
  let previous = '\0';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '#' && !opened) return result;
    result += c;
    if (c === '"' && previous !== '\\') {
      if (opened) return result;
      opened = true;
    }
    previous = c;
  }
  return result;
}

// Mirrors SecurePropertiesTool.getComment: returns the trailing comment
// (starting at '#'), tracking (naively) quote-open state the same way the
// original does.
function getComment(line) {
  let result = '';
  let startedComment = false;
  let openedValue = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '#' && !openedValue) startedComment = true;
    if (c === '"') openedValue = !openedValue;
    if (startedComment) result += c;
  }
  return result;
}

function applyOverFileValue(MuleCrypto, action, algorithm, mode, key, useRandomIVs, value) {
  if (action === 'encrypt') {
    return '![' + MuleCrypto.encryptString(algorithm, mode, key, value, useRandomIVs) + ']';
  }
  const m = value.match(WRAP_RE);
  if (m) {
    return MuleCrypto.decryptString(algorithm, mode, key, m[1], useRandomIVs);
  }
  return value;
}

// Mirrors SecurePropertiesTool.processFileLine. Returns the processed line
// (without a trailing newline).
function processFileLine(MuleCrypto, line, action, algorithm, mode, key, useRandomIVs, separator, space) {
  const comments = getComment(line);
  const stripped = removeComment(line);

  if (!stripped.includes(separator)) {
    return comments;
  }

  const inPart = stripped.split(separator)[0];
  let out = inPart + separator;
  const value = stripped.substring(inPart.length + 1).trim();

  if (value.length > 0) {
    if (space) out += ' ';
    const splitted = value.includes(ESCAPED_DOUBLE_QUOTE) ? [value] : javaSplit(value, '"');
    if (splitted.length === 0) {
      out += '"' + applyOverFileValue(MuleCrypto, action, algorithm, mode, key, useRandomIVs, '') + '"';
    } else if (splitted.length === 1) {
      out += applyOverFileValue(MuleCrypto, action, algorithm, mode, key, useRandomIVs, value);
    } else {
      out += '"' + applyOverFileValue(MuleCrypto, action, algorithm, mode, key, useRandomIVs, splitted[1]) + '"';
    }
  }

  if (comments.length > 0) {
    out += ' ' + comments;
  }
  return out;
}

// Mirrors how Files.lines() tokenizes a file: split on \n, \r\n, or \r, with
// no phantom empty final line just because the file ends with a terminator.
function splitJavaLines(text) {
  const hadTrailingNewline = /\r\n$|\r$|\n$/.test(text);
  const lines = text.split(/\r\n|\r|\n/);
  if (hadTrailingNewline && lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop();
  }
  return lines;
}

// Mirrors SecurePropertiesTool.applyOverFile. `format` is 'properties' or
// 'yaml'. Per-line errors (e.g. a bad key length) are collected and thrown
// together at the end, same as the CLI's behavior of finishing the file and
// reporting all errors, rather than aborting on the first one - except here
// we still return the partial output so the caller can show what happened.
export function applyOverFile(MuleCrypto, action, algorithm, mode, key, useRandomIVs, fileText, format) {
  const separator = format === 'yaml' ? ':' : '=';
  const space = format === 'yaml';
  const lines = splitJavaLines(fileText);
  const errors = [];
  let out = '';

  for (const line of lines) {
    if (line.trim().length === 0) {
      out += '\n';
      continue;
    }
    try {
      out += processFileLine(MuleCrypto, line, action, algorithm, mode, key, useRandomIVs, separator, space) + '\n';
    } catch (err) {
      errors.push(`${err.message} (line: ${line})`);
      out += line + '\n';
    }
  }

  if (errors.length > 0) {
    const err = new Error(errors.join('\n'));
    err.partialOutput = out;
    throw err;
  }
  return out;
}
