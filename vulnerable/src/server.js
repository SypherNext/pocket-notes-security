import { createApp } from './app.js';
import { config } from './config.js';

// 127.0.0.1 only: the app is reachable from this computer and nowhere else.
createApp().listen(config.port, '127.0.0.1', (err) => {
  if (err) throw err;
  console.log(`Pocket Notes (VULNERABLE practice app) on http://127.0.0.1:${config.port}`);
  console.log('Never expose this app to a network.');
});
