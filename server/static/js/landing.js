(() => {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const items = document.querySelectorAll('.landing-reveal');
  if (reduced || !('IntersectionObserver' in window)) items.forEach(el => el.classList.add('is-visible'));
  else {
    const observer = new IntersectionObserver(entries => entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('is-visible'); observer.unobserve(entry.target); }
    }), {threshold: .12});
    items.forEach(el => observer.observe(el));
  }
  const nav = document.querySelector('.landing-nav');
  const menu = document.querySelector('.landing-menu');
  if (nav && menu) {
    menu.addEventListener('click', () => {
      const open = nav.classList.toggle('is-open');
      menu.setAttribute('aria-expanded', String(open));
    });
    nav.querySelectorAll('nav a').forEach(a => a.addEventListener('click', () => {
      nav.classList.remove('is-open'); menu.setAttribute('aria-expanded', 'false');
    }));
  }
  const demo = document.querySelector('[data-landing-demo]');
  if (!demo) return;
  const tabs = [...demo.querySelectorAll('[data-demo-tab]')];
  const panels = [...demo.querySelectorAll('[data-demo-panel]')];
  let active = 0, timer;
  const stop = () => { if (timer) clearInterval(timer); timer = null; };
  const select = (name, manual = false) => {
    const next = tabs.findIndex(tab => tab.dataset.demoTab === name);
    if (next < 0) return;
    active = next;
    tabs.forEach((tab, index) => {
      const selected = index === active;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach(panel => panel.classList.toggle('is-active', panel.dataset.demoPanel === name));
    if (manual) stop();
  };
  tabs.forEach(tab => {
    tab.addEventListener('click', () => select(tab.dataset.demoTab, true));
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft','ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      const next = (active + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      select(tabs[next].dataset.demoTab, true); tabs[next].focus();
    });
  });
  document.querySelectorAll('[data-open-demo]').forEach(link => link.addEventListener('click', () => select(link.dataset.openDemo, true)));
  if (!reduced) timer = setInterval(() => select(tabs[(active + 1) % tabs.length].dataset.demoTab), 6500);
})();

