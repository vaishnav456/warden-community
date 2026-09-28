document.addEventListener('submit', (event) => {
  const form = event.target.closest('.login-form');
  if (!form) return;
  const button = form.querySelector('.login-submit');
  if (!button) return;
  button.classList.add('is-loading');
  button.setAttribute('aria-busy', 'true');
  button.disabled = true;
});
