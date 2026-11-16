import { verifyWithJwks } from 'hono/jwt';

// Disconnected prototype. Only a server-created, one-time challenge bound to
// the current session may supply expectedNonce and expectedSubject. This helper
// does not consume challenges and must not be used alone to authorize deletion.
const GOOGLE_KEYS = 'https://www.googleapis.com/oauth2/v3/certs';
const MAX_TOKEN_AGE = 600;
const MAX_AUTH_AGE = 300;
const CLOCK_SKEW = 30;

export async function verifyGoogleReauthToken(idToken, clientId, expectedNonce, expectedSubject, now) {
	if (typeof idToken !== 'string' || idToken.length > 16384 ||
		typeof clientId !== 'string' || !clientId ||
		typeof expectedNonce !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(expectedNonce) ||
		typeof expectedSubject !== 'string' || !expectedSubject ||
		!Number.isSafeInteger(now) || now < 0) return false;
	try {
		// The key URL is fixed in server code; never accept it from the client.
		const payload = await verifyWithJwks(idToken, {
			jwks_uri: GOOGLE_KEYS,
			allowedAlgorithms: ['RS256'],
			verification: { aud: clientId },
		});
		if (!['https://accounts.google.com', 'accounts.google.com'].includes(payload.iss) ||
			payload.sub !== expectedSubject ||
			(typeof payload.azp === 'string' && payload.azp !== clientId) ||
			(Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId) ||
			!Number.isSafeInteger(payload.exp) || payload.exp <= now ||
			!Number.isSafeInteger(payload.iat) || payload.iat > now + CLOCK_SKEW || payload.iat < now - MAX_TOKEN_AGE ||
			!Number.isSafeInteger(payload.auth_time) || payload.auth_time > now + CLOCK_SKEW ||
			payload.auth_time < now - MAX_AUTH_AGE || payload.auth_time > payload.iat + CLOCK_SKEW ||
			typeof payload.nonce !== 'string') return false;
		const encoder = new TextEncoder();
		const [actual, expected] = await Promise.all([
			crypto.subtle.digest('SHA-256', encoder.encode(payload.nonce)),
			crypto.subtle.digest('SHA-256', encoder.encode(expectedNonce)),
		]);
		return crypto.subtle.timingSafeEqual(actual, expected);
	} catch {
		return false;
	}
}
