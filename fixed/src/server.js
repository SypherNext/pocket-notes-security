import { createApp } from './app.js';
import { config } from './config.js';

config.mailApiKey(); // fail at start-up, not at the first email, if the secret is missing

// 127.0.0.1 only: the app is reachable from this computer and nowhere else.
createApp().listen(config.port, '127.0.0.1', (err) => {
  if (err) throw err;
  console.log(`Pocket Notes (fixed) on http://localhost:${config.port}`);
});
