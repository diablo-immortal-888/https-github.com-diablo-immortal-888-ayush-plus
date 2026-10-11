import { isIP } from 'node:net';

const errors = [];
const warnings = [];
const required = name => {
  const value = process.env[name]?.trim();
  if (!value || /^(?:your-|replace-with|example|changeme|todo)/i.test(value)) {
    errors.push(`${name} is missing or still contains a placeholder.`);
    return '';
  }
  return value;
};

if (process.env.NODE_ENV !== 'production') errors.push('NODE_ENV must be production.');

const domain = required('PUBLIC_DOMAIN');
if (domain) {
  if (domain.includes('://') || domain.includes('/') || domain.includes(':') || isIP(domain)) {
    errors.push('PUBLIC_DOMAIN must be a DNS hostname only, without scheme, port, path, or IP address.');
  } else {
    try {
      const parsed = new URL(`https://${domain}`);
      if (parsed.hostname !== domain || !domain.includes('.')) errors.push('PUBLIC_DOMAIN must be a fully qualified DNS hostname.');
    } catch {
      errors.push('PUBLIC_DOMAIN must be a valid DNS hostname.');
    }
  }
}

const origin = required('PUBLIC_ORIGIN');
if (origin) {
  try {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      errors.push('PUBLIC_ORIGIN must be an exact HTTPS origin with no path, query, or fragment.');
    }
    if (domain && parsed.hostname !== domain) errors.push('PUBLIC_ORIGIN hostname must exactly match PUBLIC_DOMAIN.');
  } catch {
    errors.push('PUBLIC_ORIGIN must be a valid HTTPS origin.');
  }
}

const acmeEmail = required('ACME_EMAIL');
if (acmeEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(acmeEmail)) errors.push('ACME_EMAIL must be a valid contact email address.');

const googleClientId = required('GOOGLE_CLIENT_ID');
if (googleClientId && !/^[\w-]+\.apps\.googleusercontent\.com$/.test(googleClientId)) errors.push('GOOGLE_CLIENT_ID must be a Google OAuth Web client ID.');

const rawEncryptionKey = required('DATA_ENCRYPTION_KEY');
if (rawEncryptionKey) {
  const key = Buffer.from(rawEncryptionKey, 'base64');
  if (key.length !== 32 || key.toString('base64') !== rawEncryptionKey) {
    errors.push('DATA_ENCRYPTION_KEY must be canonical base64 encoding of exactly 32 random bytes.');
  }
}

if (!process.env.OPENAI_API_KEY?.trim()) warnings.push('OPENAI_API_KEY is not set; AI analysis and OpenAI speech will be unavailable.');
if (!process.env.GOOGLE_TTS_API_KEY?.trim() && !process.env.OPENAI_API_KEY?.trim()) warnings.push('Neither Google TTS nor OpenAI speech is configured.');
if (!process.env.GOOGLE_TRANSLATE_API_KEY?.trim()) warnings.push('GOOGLE_TRANSLATE_API_KEY is not set; full-page translation will be unavailable.');
if (!process.env.OPENAI_MODEL?.trim()) warnings.push('OPENAI_MODEL is not set; the server will use its default model. Confirm that the selected model is enabled for the API project.');

for (const warning of warnings) console.warn(`WARNING: ${warning}`);
if (errors.length) {
  for (const error of errors) console.error(`ERROR: ${error}`);
  console.error(`Production preflight failed with ${errors.length} configuration issue(s). No secret values were displayed.`);
  process.exitCode = 1;
} else {
  console.log('Production configuration preflight passed. Secret values were not displayed.');
}
