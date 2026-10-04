'use strict';
(() => {
  const tokenInput = document.getElementById('recovery-token');
  if (!tokenInput) return;
  const fragment = new URLSearchParams(window.location.hash.slice(1)).get('token');
  if (fragment && /^[A-Za-z0-9_-]{43}$/.test(fragment)) tokenInput.value = fragment;
  if (window.location.hash) window.history.replaceState(null, '', window.location.pathname);
  const valid = /^[A-Za-z0-9_-]{43}$/.test(tokenInput.value);
  document.getElementById('recovery-link-error')?.classList.toggle('hidden', valid);
  const submit = document.querySelector('#recovery-form button[type="submit"]');
  if (submit) submit.disabled = !valid;
})();
