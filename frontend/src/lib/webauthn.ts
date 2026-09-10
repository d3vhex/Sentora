/**
 * The browser half of a WebAuthn ceremony.
 *
 * All of this is type conversion, and it is here rather than in a page because
 * getting it wrong fails in a way that names nothing. `navigator.credentials`
 * wants `ArrayBuffer` for the challenge and every credential id; the server
 * speaks JSON and therefore base64url. Hand a string where a buffer is
 * expected and Chrome throws `TypeError: Failed to execute 'create' on
 * 'CredentialsContainer'`, which says neither which field nor why.
 *
 * base64url is not base64. `-` and `_` stand in for `+` and `/`, and the
 * padding is dropped. `atob` accepts neither substitution, so decoding without
 * translating first produces `InvalidCharacterError` on roughly one challenge
 * in three - the two alphabets agree until a byte happens to land on one of
 * those characters, which is exactly the kind of bug that passes a demo and
 * fails in the field.
 */

export function base64urlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToBase64url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = '';
  // Not `String.fromCharCode(...bytes)`. Spreading a large attestation object
  // into an argument list overflows the call stack on some browsers, and an
  // attestation is comfortably big enough to do it.
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Is the API even present? False on plain http and in older browsers. */
export function supported(): boolean {
  return typeof window !== 'undefined'
    && !!window.PublicKeyCredential
    && !!navigator.credentials;
}

/** Register a new credential from the server's options. */
export async function createCredential(options: any) {
  const publicKey: any = {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: { ...options.user, id: base64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c: any) => ({
      ...c, id: base64urlToBuffer(c.id),
    })),
  };

  const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential;
  if (!credential) throw new Error('The browser returned no credential.');
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    // Reported by the authenticator and stored, so the console can say "USB
    // security key" rather than "Security key" in the list.
    transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
    },
  };
}

/** Assert an existing credential from the server's options. */
export async function getAssertion(options: any) {
  const publicKey: any = {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c: any) => ({
      ...c, id: base64urlToBuffer(c.id),
    })),
  };

  const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential;
  if (!credential) throw new Error('The browser returned no assertion.');
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
  };
}

/**
 * What went wrong, in words an operator can act on.
 *
 * The browser's own messages are deliberately vague — telling a page exactly
 * why a ceremony failed is a fingerprinting surface — so the useful signal is
 * the error *name*, and the raw `message` is usually empty or generic.
 */
export function explain(err: any): string {
  const name = err?.name || '';
  if (name === 'NotAllowedError') {
    return 'The request was cancelled or timed out. Touch the key when it '
      + 'lights up, or try again.';
  }
  if (name === 'InvalidStateError') {
    return 'That key is already registered on this account.';
  }
  if (name === 'SecurityError') {
    return 'The browser refused this origin. A security key needs https and a '
      + 'hostname — an IP address cannot be used.';
  }
  if (name === 'NotSupportedError') {
    return 'This authenticator does not support what the server asked for.';
  }
  if (name === 'AbortError') {
    return 'The request was aborted.';
  }
  return err?.message || 'The security key could not be used.';
}
