'use strict';
(() => {
  const form = document.getElementById('helpdesk-form-editor');
  if (!form) return;
  const questions = document.getElementById('helpdesk-questions');
  const add = document.getElementById('helpdesk-add-question');
  const error = document.getElementById('helpdesk-form-error');
  const template = document.getElementById('helpdesk-question-template');
  const ruleTemplate = document.getElementById('helpdesk-condition-template');
  const branchOptions = Array.from(document.getElementById('helpdesk-branch-options').options).map(option => [option.value, option.textContent]);
  const lines = value => value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
  function populate(select, choices, selected) {
    select.replaceChildren();
    choices.forEach(([value, label]) => select.add(new Option(label, value)));
    if (selected && !choices.some(([value]) => value === selected)) select.add(new Option('Previous value: ' + selected, selected));
    if (selected) select.value = selected;
  }
  function makeRule(rule = {}) {
    const row = ruleTemplate.content.firstElementChild.cloneNode(true);
    row.dataset.source = rule.source === 'field' ? 'field:' + rule.field : rule.source || 'category';
    row.dataset.value = rule.value || '';
    row.querySelector('[data-rule-operator]').value = rule.operator || 'equals';
    return row;
  }
  function update() {
    add.disabled = questions.children.length >= 8;
    const preceding = [];
    Array.from(questions.children).forEach((row, index) => {
      row.querySelector('h2').textContent = 'Question ' + (index + 1);
      row.querySelector('[data-question-action="up"]').disabled = index === 0;
      row.querySelector('[data-question-action="down"]').disabled = index === questions.children.length - 1;
      const dropdown = row.querySelector('[name="field_type"]').value === 'select';
      row.querySelector('.helpdesk-options').classList.toggle('hidden', !dropdown);
      row.querySelector('[name="field_options"]').required = dropdown;
      const mode = row.querySelector('.helpdesk-show-mode').value;
      const rules = row.querySelector('.helpdesk-rules');
      row.querySelector('.helpdesk-conditions').classList.toggle('hidden', mode === 'always');
      if (mode !== 'always' && !rules.children.length) rules.appendChild(makeRule());
      row.querySelector('.helpdesk-add-rule').disabled = rules.children.length >= 4;
      const checked = [];
      Array.from(rules.children).forEach(rule => {
        const source = rule.querySelector('[data-rule-source]');
        populate(source, [['category', 'Category'], ['priority', 'Priority'], ['branch', 'Assigned branch'],
          ...preceding.map(field => ['field:' + field.id, 'Answer: ' + field.label])], rule.dataset.source);
        const valueText = rule.querySelector('[data-rule-text]');
        const valueChoice = rule.querySelector('[data-rule-choice]');
        let choices = [];
        if (source.value === 'category') choices = lines(form.elements.categories.value).map(value => [value, value]);
        if (source.value === 'priority') choices = ['low', 'normal', 'high', 'urgent'].map(value => [value, value]);
        if (source.value === 'branch') choices = branchOptions;
        if (source.value.startsWith('field:')) {
          const field = preceding.find(item => item.id === source.value.slice(6));
          if (field?.type === 'select') choices = field.options.map(value => [value, value]);
        }
        const useChoice = choices.length > 0;
        valueText.classList.toggle('hidden', useChoice);
        valueChoice.classList.toggle('hidden', !useChoice);
        if (useChoice) populate(valueChoice, choices, rule.dataset.value);
        else valueText.value = rule.dataset.value;
        const value = useChoice ? valueChoice.value : valueText.value;
        rule.dataset.value = value;
        const record = {source: source.value.startsWith('field:') ? 'field' : source.value,
          operator: rule.querySelector('[data-rule-operator]').value, value};
        if (record.source === 'field') record.field = source.value.slice(6);
        checked.push(record);
      });
      row.querySelector('[name="field_condition"]').value = JSON.stringify(mode === 'always' ? null : {mode, rules: checked});
      preceding.push({id: row.querySelector('[name="field_id"]').value,
        label: row.querySelector('[name="field_label"]').value || 'Untitled question',
        type: row.querySelector('[name="field_type"]').value, options: lines(row.querySelector('[name="field_options"]').value)});
    });
  }
  Array.from(questions.children).forEach(row => {
    const condition = JSON.parse(row.querySelector('[name="field_condition"]').value || 'null');
    condition?.rules.forEach(rule => row.querySelector('.helpdesk-rules').appendChild(makeRule(rule)));
  });
  add.addEventListener('click', () => {
    if (questions.children.length >= 8) return;
    const row = template.content.firstElementChild.cloneNode(true);
    const bytes = new Uint8Array(12);
    window.crypto.getRandomValues(bytes);
    const id = 'q_' + Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    row.querySelector('[name="field_id"]').value = id;
    row.querySelector('[name="field_required"]').value = id;
    questions.appendChild(row); update();
    row.querySelector('[name="field_label"]').focus();
  });
  function changed(event) {
    const rule = event.target.closest('.helpdesk-rule');
    if (rule) {
      if (event.target.matches('[data-rule-source]')) {rule.dataset.source = event.target.value; rule.dataset.value = '';}
      if (event.target.matches('[data-rule-text], [data-rule-choice]')) rule.dataset.value = event.target.value;
    }
    update();
  }
  questions.addEventListener('change', changed);
  questions.addEventListener('input', changed);
  form.elements.categories.addEventListener('input', update);
  questions.addEventListener('click', event => {
    const action = event.target.closest('[data-question-action]');
    if (action) {
      const row = action.closest('.helpdesk-question');
      if (action.dataset.questionAction === 'remove') row.remove();
      if (action.dataset.questionAction === 'up' && row.previousElementSibling) questions.insertBefore(row, row.previousElementSibling);
      if (action.dataset.questionAction === 'down' && row.nextElementSibling) questions.insertBefore(row.nextElementSibling, row);
    }
    const addRule = event.target.closest('.helpdesk-add-rule');
    if (addRule) {
      const rules = addRule.closest('.helpdesk-question').querySelector('.helpdesk-rules');
      if (rules.children.length < 4) rules.appendChild(makeRule());
    }
    if (event.target.closest('.helpdesk-remove-rule')) event.target.closest('.helpdesk-rule').remove();
    update();
  });
  form.addEventListener('submit', event => {
    update(); error.textContent = '';
    const categories = lines(form.elements.categories.value);
    if (!categories.length || categories.length > 12 || new Set(categories.map(value => value.toLowerCase())).size !== categories.length) {
      event.preventDefault(); error.textContent = 'Enter one to twelve unique categories.'; form.elements.categories.focus();
    }
  });
  update();
})();
