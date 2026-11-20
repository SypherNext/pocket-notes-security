// FLAW (lesson 11): secrets written into the source code. Anyone with the repository has them,
// and they stay in the git history even after someone deletes these lines.
// Both values are fake and only exist in this practice app.
export const config = {
  port: Number(process.env.PORT ?? 18401),
  mailApiKey: 'pn_live_8f3a9c2e71d04b6fa5e9c3d2b1a07f64',
  adminResetToken: 'reset-me-please-2026',
};
