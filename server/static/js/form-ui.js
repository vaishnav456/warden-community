/* Warden-owned validation, confirmation, and warning interactions.
   This intentionally avoids native alert/confirm/validation bubbles so the
   same accessible UI is used on every browser and operating system. */
(function () {
  'use strict';

  function fieldLabel(field) {
    const label = field.dataset.validationLabel || field.labels?.[0]?.textContent || field.name || 'This field';
    return String(label).replace(/\s+/g, ' ').trim();
  }

  function validationMessage(field) {
    const label = fieldLabel(field);
    const validity = field.validity;
    if (validity.valueMissing) return `${label} is required.`;
    if (validity.typeMismatch && field.type === 'email') return `Enter a complete email address, such as name@company.com.`;
    if (validity.typeMismatch && field.type === 'url') return `Enter a complete address beginning with https://.`;
    if (validity.tooShort) return `${label} must contain at least ${field.minLength} characters.`;
    if (validity.tooLong) return `${label} must contain no more than ${field.maxLength} characters.`;
    if (validity.rangeUnderflow) return `${label} must be ${field.min} or greater.`;
    if (validity.rangeOverflow) return `${label} must be ${field.max} or less.`;
    if (validity.stepMismatch) return `${label} must use a permitted increment.`;
    if (validity.patternMismatch) return field.dataset.patternMessage || `${label} is not in the expected format.`;
    if (validity.badInput) return `Enter a valid value for ${label.toLowerCase()}.`;
    if (validity.customError) return field.validationMessage;
    return `Check ${label.toLowerCase()} and try again.`;
  }

  function errorId(field) {
    if (!field.dataset.wardenValidationId) {
      field.dataset.wardenValidationId = `warden-field-error-${Math.random().toString(36).slice(2, 10)}`;
    }
    return field.dataset.wardenValidationId;
  }

  function clearFieldError(field) {
    field.classList.remove('warden-field-invalid');
    field.removeAttribute('aria-invalid');
    const id = field.dataset.wardenValidationId;
    if (id) document.getElementById(id)?.remove();
    const describedBy = (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(value => value && value !== id);
    if (describedBy.length) field.setAttribute('aria-describedby', describedBy.join(' '));
    else field.removeAttribute('aria-describedby');
  }

  function showFieldError(field) {
    if (!field.willValidate) return;
    clearFieldError(field);
    const id = errorId(field);
    const error = document.createElement('div');
    error.id = id;
    error.className = 'warden-field-error';
    error.setAttribute('role', 'alert');
    error.textContent = validationMessage(field);
    field.classList.add('warden-field-invalid');
    field.setAttribute('aria-invalid', 'true');
    const describedBy = (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
    field.setAttribute('aria-describedby', [...new Set([...describedBy, id])].join(' '));
    field.insertAdjacentElement('afterend', error);
  }

  function checkMatches(field) {
    const selector = field.dataset.match;
    if (!selector) return;
    const source = document.querySelector(selector);
    field.setCustomValidity(source && field.value !== source.value ? (field.dataset.matchMessage || 'The values do not match.') : '');
  }

  document.addEventListener('invalid', (event) => {
    const field = event.target;
    if (!(field instanceof HTMLInputElement || field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement)) return;
    event.preventDefault();
    field.form?.classList.add('warden-validation-attempted');
    showFieldError(field);
    if (field.form && !field.form.dataset.wardenInvalidFocusQueued) {
      field.form.dataset.wardenInvalidFocusQueued = '1';
      requestAnimationFrame(() => {
        field.focus({ preventScroll: true });
        field.scrollIntoView({ behavior: 'smooth', block: 'center' });
        delete field.form.dataset.wardenInvalidFocusQueued;
        window.wardenToast?.('Please check the highlighted fields.', 'warning');
      });
    }
  }, true);

  document.addEventListener('input', (event) => {
    const field = event.target;
    if (!(field instanceof HTMLInputElement || field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement)) return;
    checkMatches(field);
    if (field.validity.valid) clearFieldError(field);
    else if (field.form?.classList.contains('warden-validation-attempted')) showFieldError(field);
  }, true);

  document.addEventListener('change', (event) => {
    const field = event.target;
    if (!(field instanceof HTMLInputElement || field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement)) return;
    checkMatches(field);
    if (field.validity.valid) clearFieldError(field);
  }, true);

  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    for (const field of form.querySelectorAll('[data-match]')) checkMatches(field);
    if (!form.checkValidity()) event.preventDefault();
  }, true);

  function setupActionDialog() {
    const dialog = document.getElementById('warden-action-dialog');
    if (!dialog) return;
    const title = dialog.querySelector('[data-dialog-title]');
    const message = dialog.querySelector('[data-dialog-message]');
    const detail = dialog.querySelector('[data-dialog-detail]');
    const inputWrap = dialog.querySelector('[data-dialog-input-wrap]');
    const input = dialog.querySelector('[data-dialog-input]');
    const confirmButton = dialog.querySelector('[data-dialog-confirm]');
    const cancelButton = dialog.querySelector('[data-dialog-cancel]');
    let resolver = null;
    let mode = 'confirm';

    function finish(value) {
      dialog.close();
      resolver?.(value);
      resolver = null;
    }

    window.wardenConfirm = function (options) {
      const config = typeof options === 'string' ? { message: options } : (options || {});
      resolver?.(false);
      mode = 'confirm';
      title.textContent = config.title || 'Confirm action';
      message.textContent = config.message || 'Are you sure you want to continue?';
      detail.textContent = config.detail || '';
      detail.hidden = !config.detail;
      inputWrap.hidden = true;
      confirmButton.textContent = config.confirmLabel || 'Continue';
      dialog.dataset.tone = config.tone || 'warning';
      dialog.showModal();
      confirmButton.focus();
      return new Promise(resolve => { resolver = resolve; });
    };

    window.wardenPrompt = function (options) {
      const config = typeof options === 'string' ? { message: options } : (options || {});
      resolver?.(null);
      mode = 'prompt';
      title.textContent = config.title || 'More information required';
      message.textContent = config.message || 'Enter the requested information.';
      detail.textContent = config.detail || '';
      detail.hidden = !config.detail;
      inputWrap.hidden = false;
      input.value = config.value || '';
      input.placeholder = config.placeholder || '';
      input.dataset.validationLabel = config.label || 'Reason';
      input.required = config.required !== false;
      confirmButton.textContent = config.confirmLabel || 'Continue';
      dialog.dataset.tone = config.tone || 'warning';
      dialog.showModal();
      input.focus();
      return new Promise(resolve => { resolver = resolve; });
    };

    confirmButton.addEventListener('click', () => {
      if (mode === 'prompt') {
        if (!input.checkValidity()) { input.reportValidity(); return; }
        finish(input.value.trim());
      } else finish(true);
    });
    cancelButton.addEventListener('click', () => finish(mode === 'prompt' ? null : false));
    dialog.addEventListener('cancel', (event) => { event.preventDefault(); finish(mode === 'prompt' ? null : false); });
    dialog.addEventListener('click', (event) => { if (event.target === dialog) finish(mode === 'prompt' ? null : false); });
    input.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); confirmButton.click(); } });
    document.body.addEventListener('htmx:confirm', (event) => {
      if (!event.detail.question) return;
      event.preventDefault();
      window.wardenConfirm({
        title: 'Confirm queued action', message: event.detail.question,
        detail: 'The request and its result will be recorded in Jobs and the Audit log.',
        tone: 'danger', confirmLabel: 'Continue',
      }).then(confirmed => { if (confirmed) event.detail.issueRequest(true); });
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setupActionDialog);
  else setupActionDialog();
})();
