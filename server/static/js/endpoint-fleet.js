/* Read-only fleet refresh and locally saved filter views; no endpoint mutations. */
(() => {
  function start() {
    const root = document.getElementById('endpoint-fleet');
    if (!root || root.dataset.refreshStarted) return;
    root.dataset.refreshStarted = '1';
    const status = document.getElementById('fleet-refresh-status');
    const select = document.getElementById('fleet-saved-views');
    const key = 'warden:fleet-views:' + root.dataset.viewScope;
    let views = [];
    try { views = JSON.parse(localStorage.getItem(key) || '[]'); } catch (_) {}
    if (!Array.isArray(views)) views = [];
    views = views.filter(v => v && typeof v.name === 'string' && typeof v.query === 'string').slice(0, 20);
    function renderViews() {
      select.replaceChildren(new Option('Saved views (this browser)', ''));
      views.forEach((v, i) => select.add(new Option(v.name, String(i))));
    }
    function saveViews() {
      try { localStorage.setItem(key, JSON.stringify(views)); renderViews(); }
      catch (_) { status.textContent = 'Browser storage unavailable; view could not be saved.'; }
    }
    renderViews();
    document.getElementById('fleet-save-view').addEventListener('click', () => {
      const name = window.prompt('Name this endpoint view (saved only in this browser):');
      if (!name || !name.trim()) return;
      const query = new URLSearchParams(location.search);
      query.delete('page');
      views = views.filter(v => v.name !== name.trim()).slice(-19);
      views.push({ name: name.trim().slice(0, 80), query: query.toString() }); saveViews();
    });
    select.addEventListener('change', () => {
      const view = views[Number(select.value)];
      if (select.value !== '' && view) location.assign('/endpoints?' + view.query);
    });
    document.getElementById('fleet-delete-view').addEventListener('click', () => {
      if (!views.length) return;
      const name = window.prompt('Enter the name of the saved view to delete:');
      if (name === null) return;
      views = views.filter(v => v.name !== name.trim()); saveViews();
    });
    let busy = false;
    function paused() {
      return document.hidden || !document.getElementById('fleet-auto-refresh').checked
        || root.querySelector('details[open], .fleet-device-check:checked')
        || (root.contains(document.activeElement) && document.activeElement !== document.body)
        || Array.from(root.querySelectorAll('.endpoint-modal-backdrop')).some(el => el.getClientRects().length);
    }
    const timer = setInterval(async () => {
      if (!root.isConnected) { clearInterval(timer); return; }
      if (busy || paused()) { status.textContent = 'Refresh paused while you interact or select devices.'; return; }
      busy = true;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      try {
        const response = await fetch(location.href, { cache: 'no-store', credentials: 'same-origin', signal: controller.signal,
          headers: { 'X-Fleet-Refresh': '1', 'Accept': 'application/json' } });
        if (!response.ok || response.redirected) throw new Error('Refresh unavailable');
        const data = await response.json();
        if (typeof data.rows !== 'string' || !data.summary) throw new Error('Refresh unavailable');
        const doc = new DOMParser().parseFromString('<table><tbody id="endpoint-table-body">' + data.rows + '</tbody></table><nav class="fleet-pagination">' + data.pagination + '</nav>', 'text/html');
        // Check again after network response: do not overwrite a newly focused/selected row.
        if (!paused()) {
          for (const selector of ['#endpoint-table-body', '.fleet-pagination']) {
            const from = doc.querySelector(selector), to = root.querySelector(selector);
            if (from && to) to.replaceChildren(...Array.from(from.childNodes).map(node => document.importNode(node, true)));
          }
          const counts = [data.summary.total, data.summary.online, data.summary.total - data.summary.online, data.summary.attention];
          root.querySelectorAll('.fleet-summary-strip strong').forEach((el, index) => { el.textContent = counts[index]; });
          root.querySelector('.fleet-results-note').textContent = 'Showing ' + data.shown + ' of ' + data.total + ' matches · Page ' + data.page + ' of ' + data.pages + '. Health is based on reported evidence.';
          status.textContent = 'Updated ' + new Date().toLocaleTimeString();
        }
      } catch (_) { status.textContent = 'Refresh failed; current data retained. Will retry.'; }
      finally { clearTimeout(timeout); busy = false; }
    }, 30000);
  }
  document.addEventListener('DOMContentLoaded', start);
  document.addEventListener('htmx:afterSettle', start);
})();
