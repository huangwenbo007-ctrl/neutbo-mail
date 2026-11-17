// Environment credentials must be supplied as a pair; never mix clients.
export function googleCredentials(env, setting) {
  const id = env.google_oauth_client_id;
  const secret = env.google_oauth_client_secret;
  if (id || secret) {
    if (typeof id !== 'string' || !id || typeof secret !== 'string' || !secret) {
      return null;
    }
    return { id, secret };
  }
  if (!setting.googleClientId || !setting.googleClientSecret) return null;
  return { id: setting.googleClientId, secret: setting.googleClientSecret };
}
