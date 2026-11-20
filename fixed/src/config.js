// Secrets come from the environment (a .env file that is never committed, or the CI secret store).
// The admin reset backdoor is gone completely: there is no token to leak.
const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable ${name}`);
  return value;
};

export const config = {
  port: Number(process.env.PORT ?? 18402),
  mailApiKey: () => required('MAIL_API_KEY'),
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? 'http://localhost:18402').split(',').filter(Boolean),
};
