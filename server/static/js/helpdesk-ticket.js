'use strict';
(() => {
  const form = document.getElementById('helpdesk-ticket-form');
  if (!form) return;
  const fields = Array.from(form.querySelectorAll('.helpdesk-ticket-field')).map(row => ({
    row, input: row.querySelector('input,select'), id: row.dataset.fieldId,
    condition: JSON.parse(row.dataset.condition || 'null'), required: row.dataset.required === 'true'
  }));
  function update() {
    const context = {
      branch: form.elements.endpoint_id.selectedOptions[0]?.dataset.branch || '',
      category: form.elements.category.value,
      priority: form.elements.priority.value
    };
    const answers = {};
    fields.forEach(field => {
      const condition = field.condition;
      const matches = condition?.rules.map(rule => {
        const actual = rule.source === 'field' ? answers[rule.field] || '' : context[rule.source] || '';
        return rule.operator === 'equals' ? actual === rule.value : actual !== rule.value;
      });
      const visible = !condition || (condition.mode === 'all' ? matches.every(Boolean) : matches.some(Boolean));
      field.row.classList.toggle('hidden', !visible);
      field.input.disabled = !visible;
      field.input.required = visible && field.required;
      if (!visible) field.input.value = '';
      else answers[field.id] = field.input.value.trim();
    });
  }
  form.addEventListener('input', update);
  form.addEventListener('change', update);
  update();
})();
