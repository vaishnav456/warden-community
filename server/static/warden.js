/**
 * Warden — Custom client-side JavaScript
 * Alpine.js + HTMX helpers, toast system, utility functions.
 */

// ── Toast notification system ────────────────────────────────────────────────
window.wardenToast = function(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const colors = {
    success: 'bg-emerald-600 text-white',
    error:   'bg-red-600 text-white',
    warning: 'bg-amber-500 text-white',
    info:    'bg-slate-700 text-white',
  };

  const icons = {
    success: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>',
    error:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>',
    warning: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
    info:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
  };

  const el = document.createElement('div');
  el.className = `pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg text-sm font-medium max-w-sm transition-all duration-300 translate-y-2 opacity-0 ${colors[type] || colors.info}`;
  el.innerHTML = `
    <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">${icons[type] || icons.info}</svg>
    <span class="flex-1">${message}</span>
    <button onclick="this.parentElement.remove()" class="opacity-60 hover:opacity-100 ml-1">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
      </svg>
    </button>
  `;
  container.appendChild(el);

  // Animate in
  requestAnimationFrame(() => {
    el.classList.remove('translate-y-2', 'opacity-0');
  });

  // Auto-remove
  setTimeout(() => {
    el.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => el.remove(), 300);
  }, duration);
};

// ── HTMX global error handler ─────────────────────────────────────────────────
document.addEventListener('htmx:responseError', function(e) {
  const status = e.detail.xhr.status;
  if (status === 401) {
    window.location.href = '/login';
  } else if (status === 403) {
    wardenToast('Permission denied', 'error');
  } else if (status >= 500) {
    wardenToast('Server error. Please try again.', 'error');
  }
});

document.addEventListener('htmx:sendError', function() {
  wardenToast('Network error. Check your connection.', 'warning');
});

// ── Auto-refresh access token ─────────────────────────────────────────────────
// Silently refresh before the 15-min token expires
(function() {
  let refreshTimer = null;

  function scheduleRefresh(ms) {
    if (refreshTimer) clearTimeout(refreshTimer);
    // Refresh 2 minutes before expiry
    refreshTimer = setTimeout(doRefresh, ms - 120000);
  }

  async function doRefresh() {
    try {
      const r = await fetch('/auth/refresh', { method: 'POST' });
      if (!r.ok) {
        window.location.href = '/login';
      } else {
        // Re-schedule for another 15 minutes
        scheduleRefresh(15 * 60 * 1000);
      }
    } catch(e) {
      console.warn('Token refresh failed:', e);
    }
  }

  // Start refresh cycle 13 minutes in (15 - 2 buffer)
  scheduleRefresh(13 * 60 * 1000);
})();

// ── HTMX confirm dialog ────────────────────────────────────────────────────────
document.addEventListener('htmx:confirm', function(e) {
  const msg = e.detail.question;
  if (!msg) return;
  e.preventDefault();
  if (window.confirm(msg)) {
    e.detail.issueRequest(true);
  }
});

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  // Escape closes open modals (Alpine x-cloak pattern)
  if (e.key === 'Escape') {
    document.querySelectorAll('[x-show]').forEach(el => {
      if (getComputedStyle(el).display !== 'none') {
        // Try to find Alpine component and close it
        el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      }
    });
  }
});

// ── Format utilities exposed globally ─────────────────────────────────────────
window.wardenUtil = {
  formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
    return `${bytes.toFixed(1)} ${units[i]}`;
  },
  timeAgo(isoStr) {
    if (!isoStr) return 'never';
    const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
    return `${Math.floor(diff/86400)}d ago`;
  },
};
