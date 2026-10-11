// Diagnostics must never include failed SQL, row values, credentials or DSNs.
import('./runtime.mjs').catch(()=>{console.error('Encrypted application runtime failed to start');process.exit(1);});
