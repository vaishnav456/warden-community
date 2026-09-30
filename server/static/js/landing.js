(() => {
  document.documentElement.classList.add('landing-js');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const progress = document.querySelector('.reading-progress');
  let scrollPending = false;
  const updateProgress = () => {
    const distance = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    if (progress) progress.value = distance > 0 ? Math.min(100, Math.max(0, window.scrollY / distance * 100)) : 0;
    scrollPending = false;
  };
  window.addEventListener('scroll', () => {
    if (!scrollPending) { scrollPending = true; requestAnimationFrame(updateProgress); }
  }, {passive: true});
  window.addEventListener('resize', updateProgress);
  window.addEventListener('load', updateProgress);
  updateProgress();
  const motion = document.querySelector('.motion-toggle');
  const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
  let manuallyPaused = false;
  const updateMotion = () => {
    const paused = manuallyPaused || motionPreference.matches;
    document.documentElement.classList.toggle('motion-paused', paused);
    if (!motion) return;
    motion.setAttribute('aria-pressed', String(paused));
    motion.setAttribute('aria-label', motionPreference.matches ? 'Animations disabled by your system preference' : paused ? 'Resume page animations' : 'Pause page animations');
    motion.querySelector('.motion-label').textContent = motionPreference.matches ? 'Reduced motion enabled' : paused ? 'Resume animations' : 'Pause animations';
    motion.querySelector('.motion-symbol').textContent = paused ? '▷' : 'Ⅱ';
    motion.disabled = motionPreference.matches;
  };
  if (motion) motion.addEventListener('click', () => { manuallyPaused = !manuallyPaused; updateMotion(); });
  motionPreference.addEventListener('change', updateMotion);
  updateMotion();
  const devices = [...document.querySelectorAll('[data-preview-device]')];
  const detail = document.querySelector('.preview-device-detail');
  devices.forEach(device => device.addEventListener('click', () => {
    if (!detail) return;
    devices.forEach(item => {
      const selected = item === device;
      item.classList.toggle('is-selected', selected);
      item.setAttribute('aria-pressed', String(selected));
    });
    detail.querySelector('.preview-selected-name').textContent = device.dataset.previewDevice;
    detail.querySelector('.preview-selected-host').textContent = device.dataset.previewHost;
    const status = detail.querySelector('.preview-selected-status');
    status.textContent = device.dataset.previewStatus;
    status.classList.toggle('is-muted', device.dataset.previewStatus === 'Offline');
    detail.classList.remove('is-changing');
    requestAnimationFrame(() => detail.classList.add('is-changing'));
  }));
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
  const closeMenu = () => {
    nav.classList.remove('is-open');
    menu.setAttribute('aria-expanded', 'false');
    menu.setAttribute('aria-label', 'Open navigation');
  };
  if (nav && menu) {
    menu.addEventListener('click', () => {
      const open = nav.classList.toggle('is-open');
      menu.setAttribute('aria-expanded', String(open));
      menu.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    });
    nav.querySelectorAll('nav a').forEach(link => link.addEventListener('click', closeMenu));
    document.addEventListener('click', event => { if (!nav.contains(event.target)) closeMenu(); });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && nav.classList.contains('is-open')) { closeMenu(); menu.focus(); }
    });
  }
  const demo = document.querySelector('[data-landing-demo]');
const routeChoices = [...document.querySelectorAll('[data-route-choice]')];
  const connection = document.querySelector('.connection-stage');
  const routeExplanation = document.querySelector('.route-explanation');
  routeChoices.forEach(choice => choice.addEventListener('click', () => {
    if (!connection || !routeExplanation) return;
    const relay = choice.dataset.routeChoice === 'relay';
    routeChoices.forEach(item => {
      item.classList.toggle('is-active', item === choice);
      item.setAttribute('aria-pressed', String(item === choice));
    });
    connection.classList.toggle('is-relay', relay);
    connection.querySelector('.route-name').textContent = relay ? 'Encrypted HTTPS relay' : 'Direct mTLS stream';
    connection.querySelector('.route-middle').textContent = relay ? 'Warden forwards unreadable inner TLS bytes' : 'ICE/STUN finds a peer path';
    routeExplanation.textContent = relay ?
      'If NAT or firewall restrictions prevent the direct path, both peers connect outbound to Warden over HTTPS. The relay forwards the same inner mTLS stream without decrypting file contents, filenames or grants. The relay must still be reachable.' :
      'Peers first try a direct connection using ICE/STUN. The established peer channel carries an inner mTLS connection: both sides authenticate certificates before file operations.';
  }));
  const firewallChoices = [...document.querySelectorAll('[data-firewall-view]')];
  firewallChoices.forEach(choice => choice.addEventListener('click', () => {
    firewallChoices.forEach(item => {
      item.classList.toggle('is-active', item === choice);
      item.setAttribute('aria-pressed', String(item === choice));
    });
    document.querySelectorAll('[data-firewall-panel]').forEach(panel => {
      panel.hidden = panel.dataset.firewallPanel !== choice.dataset.firewallView;
      panel.classList.toggle('is-changing', !panel.hidden);
    });
  }));
  if (!demo) return;
  const tabs = [...demo.querySelectorAll('[data-demo-tab]')];
  const panels = [...demo.querySelectorAll('[data-demo-panel]')];
  let active = 0;
  const select = name => {
    const next = tabs.findIndex(tab => tab.dataset.demoTab === name);
    if (next < 0) return;
    active = next;
    tabs.forEach((tab, index) => {
      const selected = index === active;
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach(panel => {
      const selected = panel.dataset.demoPanel === name;
      panel.classList.toggle('is-active', selected);
      panel.hidden = !selected;
    });
  };
  tabs.forEach(tab => {
    tab.addEventListener('click', () => select(tab.dataset.demoTab));
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      let next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
        (active + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      select(tabs[next].dataset.demoTab);
      tabs[next].focus();
    });
  });
  document.querySelectorAll('[data-open-demo]').forEach(link => link.addEventListener('click', () => select(link.dataset.openDemo)));
  if (tabs.length) select(tabs[0].dataset.demoTab);
})();
