/**
 * The base64url conversions, which are the part that fails intermittently.
 *
 * WebAuthn moves binary through JSON, so every challenge, credential id and
 * signature crosses this boundary twice. base64url is not base64 — `-` and `_`
 * stand in for `+` and `/`, and the padding is dropped — and `atob` accepts
 * neither substitution.
 *
 * What makes that dangerous rather than merely wrong is the failure rate. The
 * two alphabets agree until a byte lands on one of the four differing
 * characters, so a naive implementation works on most challenges and throws
 * `InvalidCharacterError` on the rest. That is a bug which passes a demo,
 * passes review, and then fails for one operator in three with a message
 * naming nothing.
 *
 * Run:
 *   cd frontend
 *   npm test
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { base64urlToBuffer, bufferToBase64url, explain } from './webauthn.ts';

const bytes = (buf: ArrayBuffer) => Array.from(new Uint8Array(buf));

describe('base64url', () => {
  test('a round trip returns the same bytes', () => {
    const original = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const encoded = bufferToBase64url(original.buffer);
    assert.deepEqual(bytes(base64urlToBuffer(encoded)), Array.from(original));
  });

  test('the output never contains the characters base64url replaces', () => {
    // 0xFB 0xFF 0xBF encodes to `+/+/` in standard base64 — the exact bytes
    // that separate the two alphabets.
    const awkward = new Uint8Array([0xfb, 0xff, 0xbf, 0xfe, 0xff]);
    const encoded = bufferToBase64url(awkward.buffer);
    assert.ok(!encoded.includes('+'), `+ leaked into ${encoded}`);
    assert.ok(!encoded.includes('/'), `/ leaked into ${encoded}`);
    assert.ok(!encoded.includes('='), `padding leaked into ${encoded}`);
  });

  test('input using - and _ decodes rather than throwing', () => {
    // What the server actually sends. `atob` refuses both characters, so a
    // decoder that forgets to translate throws InvalidCharacterError here.
    // Four base64 characters carry 24 bits, so this is three bytes.
    assert.deepEqual(bytes(base64urlToBuffer('-_-_')), [251, 255, 191]);
  });

  test('unpadded input of every length decodes', () => {
    // py_webauthn strips padding, so the decoder has to put it back. One byte
    // and two bytes need two and one `=` respectively; getting this wrong
    // fails on exactly two thirds of inputs.
    for (const [encoded, expected] of [
      ['AQ', [1]],
      ['AQI', [1, 2]],
      ['AQID', [1, 2, 3]],
      ['AQIDBA', [1, 2, 3, 4]],
    ] as [string, number[]][]) {
      assert.deepEqual(bytes(base64urlToBuffer(encoded)), expected, encoded);
    }
  });

  test('a 32-byte challenge survives, which is what every ceremony sends', () => {
    const challenge = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) challenge[i] = (i * 37) % 256;
    const encoded = bufferToBase64url(challenge.buffer);
    assert.equal(encoded.length, 43, 'unpadded base64url of 32 bytes is 43 chars');
    assert.deepEqual(bytes(base64urlToBuffer(encoded)), Array.from(challenge));
  });

  test('a large attestation does not overflow the stack', () => {
    // Not `String.fromCharCode(...bytes)`. Spreading a big attestation into an
    // argument list throws RangeError on some browsers, and an attestation is
    // comfortably big enough to do it.
    const big = new Uint8Array(200_000).fill(65);
    const encoded = bufferToBase64url(big.buffer);
    assert.equal(base64urlToBuffer(encoded).byteLength, big.length);
  });

  test('empty input is empty output, not a throw', () => {
    assert.equal(bufferToBase64url(new Uint8Array([]).buffer), '');
    assert.equal(base64urlToBuffer('').byteLength, 0);
  });
});

describe('explain', () => {
  test('a cancelled prompt says what to do', () => {
    const said = explain({ name: 'NotAllowedError' });
    assert.match(said, /cancelled|timed out/i);
  });

  test('a duplicate registration is named as one', () => {
    // Otherwise "NotAllowedError" and "you already registered this key" are
    // the same blank to the operator.
    assert.match(explain({ name: 'InvalidStateError' }), /already registered/i);
  });

  test('a refused origin points at the actual cause', () => {
    const said = explain({ name: 'SecurityError' });
    assert.match(said, /hostname|IP address/i);
  });

  test('an unknown error still returns something sayable', () => {
    assert.ok(explain({}).length > 0);
    assert.ok(explain(null).length > 0);
  });
});
