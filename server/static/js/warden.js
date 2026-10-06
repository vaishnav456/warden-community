/* Warden — Alpine.js component definitions + Chart.js helpers */

async function wardenFetchJSON(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  const response = await fetch(url, { ...options, headers });
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); }
    catch (_) { throw new Error(response.ok ? 'The server returned an invalid response.' : 'Request failed.'); }
  }
  if (!response.ok) {
    throw new Error(data.error || data.message || `Request failed (${response.status})`);
  }
  return data;
}

/* ── Alert resolve widget (alerts/list.html) ──
   alertId comes from data-alert-id on the root element. */
function alertResolveWidget() {
  return {
    note: '',
    showNote: false,
    alertId: '',
    resolving: false,
    init() {
      this.alertId = this.$el.dataset.alertId || '';
    },
    async resolve() {
      if (this.resolving) return;
      this.resolving = true;
      const fd = new FormData();
      fd.append('note', this.note);
      try {
        await wardenFetchJSON(`/alerts/${this.alertId}/resolve`, {
          method: 'POST', body: fd, headers: { 'X-CSRFToken': getCsrfToken() },
        });
        const el = document.getElementById(`alert-${this.alertId}`);
        if (el) el.remove();
      } catch (error) {
        window.wardenToast(error.message || 'Could not resolve alert', 'error');
      } finally {
        this.resolving = false;
      }
    },
  };
}

/* ── Computer topology and physical floor operations ─────────────────────── */
function topologyPage() {
  return {
    canEdit: false, loading: true, saving: false, floors: [], floor: null,
    branchId: '',
    rooms: [], placements: [], endpoints: [], placedEndpointIds: [], nodes: [], links: [], discoveredLinks: [],
    alerts: {}, history: [], discovery: {}, snapshots: [], replay: null, selectedEndpointId: '', selectedNodeId: '', selectedLinkId: '',
    search: '', mapSearch: '', statusFilter: 'all', platformFilter: 'all', viewMode: 'physical',
    heatmap: 'status', overlay: 'none', showHistory: false, showPath: false, pathStart: '', pathEnd: '', lastUpdatedLabel: 'Connecting…',
    showFloorModal: false, showRoomModal: false, showRemoteModal: false, showAssetModal: false, showLinkModal: false,
    floorForm: { building: 'Office', name: '', level_order: 0, branch_id: '', aspect_ratio: 1.778 },
    roomForm: { name: '', width: 25, height: 25, capacity: '', color: '#DCE9FF' },
    assetForm: { node_type: 'switch', name: '', ip_address: '', room_id: '', details: '' },
    linkForm: { link_type: 'ethernet', label: '' }, connectionStart: null, connectionTarget: null, connecting: false,
    remoteReason: '', remoteMode: 'full_control', dragEndpointId: '', dragPointerId: null,
    dragStartClientX: 0, dragStartClientY: 0, dragMoved: false,
    focusMap: false, showFloorRail: false, showDeviceDrawer: false, canvasZoom: 1, canvasPanX: 0, canvasPanY: 0,
    panPointerId: null, panStartClientX: 0, panStartClientY: 0, panStartX: 0, panStartY: 0,
    drawingRoom: false, roomDraft: null, roomPointerId: null, dragNodeId: '',
    refreshTimer: null,
    init() {
      this.canEdit = this.$el.dataset.canEdit === '1';
      this.branchId = this.$el.dataset.branchId || '';
      this.floorForm.branch_id = this.branchId;
      this.refresh();
      this.refreshTimer = setInterval(() => { if (!this.dragEndpointId && !this.replay) this.refresh(true); }, 15000);
    },
    destroy() { if (this.refreshTimer) clearInterval(this.refreshTimer); },
    changeBranch(value) {
      window.location.assign('/topology?branch_id=' + encodeURIComponent(value || ''));
    },
    openFloorModal() {
      this.floorForm.branch_id = this.branchId;
      this.showFloorModal = true;
    },
    stateQuery(floorId = '', snapshotId = '') {
      const params = new URLSearchParams({branch_id: this.branchId});
      if (floorId) params.set('floor_id', floorId);
      if (snapshotId) params.set('snapshot_id', snapshotId);
      return '?' + params.toString();
    },
    get floorEndpoints() {
      if (!this.floor) return [];
      return this.placements.map(placement => {
        const endpoint = this.endpoints.find(item => item.id === placement.endpoint_id);
        return endpoint ? { ...endpoint, placement } : null;
      }).filter(Boolean);
    },
    get selectedEndpoint() { return this.endpoints.find(item => item.id === this.selectedEndpointId) || null; },
    get selectedNode() { return this.nodes.find(item => item.id === this.selectedNodeId) || null; },
    get selectedLink() { return [...this.links, ...this.discoveredLinks].find(item => item.id === this.selectedLinkId) || null; },
    get unplacedEndpoints() {
      const placed = new Set(this.placedEndpointIds.map(String));
      return this.endpoints.filter(item => !placed.has(String(item.id)));
    },
    get filteredUnplaced() {
      const needle = this.search.trim().toLowerCase();
      if (!needle) return this.unplacedEndpoints;
      return this.unplacedEndpoints.filter(item => [item.hostname, item.display_name, item.local_ip, item.last_seen_ip, item.interactive_user, item.assigned_to, this.endpointAddressText(item)].some(value => String(value || '').toLowerCase().includes(needle)));
    },
    get onlineCount() { return this.floorEndpoints.filter(item => item.status === 'online').length; },
    get signedInCount() { return this.floorEndpoints.filter(item => item.interactive_user).length; },
    get attentionCount() { return this.floorEndpoints.filter(item => this.endpointNeedsAttention(item)).length; },
    get visibleFloorEndpoints() {
      const needle = this.mapSearch.trim().toLowerCase();
      return this.floorEndpoints.filter(item => {
        if (this.statusFilter !== 'all' && (this.statusFilter === 'attention' ? !this.endpointNeedsAttention(item) : item.status !== this.statusFilter)) return false;
        if (this.platformFilter !== 'all' && (item.platform || 'windows') !== this.platformFilter) return false;
        return !needle || [item.hostname, item.display_name, item.local_ip, item.interactive_user, this.endpointAddressText(item)].some(value => String(value || '').toLowerCase().includes(needle));
      });
    },
    get allVisibleLinks() { return this.viewMode === 'physical' ? this.links : [...this.links, ...this.discoveredLinks]; },
    endpointAddresses(endpoint) {
      const reported = Array.isArray(endpoint?.ip_addresses) ? endpoint.ip_addresses : [];
      if (reported.length) return reported;
      const fallback = endpoint?.local_ip || endpoint?.last_seen_ip;
      return fallback ? [{ address: fallback, cidr: fallback, family: fallback.includes(':') ? 'IPv6' : 'IPv4', interface: null, primary: true }] : [];
    },
    endpointAddressText(endpoint) { return this.endpointAddresses(endpoint).map(item => item.address).join(', '); },
    endpointAddressSummary(endpoint) {
      const addresses = this.endpointAddresses(endpoint);
      if (!addresses.length) return 'Not reported';
      return `${addresses[0].address}${addresses.length > 1 ? ` +${addresses.length - 1}` : ''}`;
    },
    get topologyObjects() {
      return [...this.floorEndpoints.map(item => ({ key: `endpoint:${item.id}`, label: item.display_name || item.hostname })), ...this.nodes.map(item => ({ key: `node:${item.id}`, label: item.name }))];
    },
    async refresh(silent = false) {
      if (!silent) this.loading = true;
      try {
        const wanted = this.floor ? this.floor.id : '';
        const query = this.stateQuery(wanted);
        const data = await wardenFetchJSON(`/topology/state${query}`);
        this.floors = data.floors || [];
        this.floor = data.floor || null;
        this.rooms = data.rooms || [];
        this.placements = data.placements || [];
        this.endpoints = data.endpoints || [];
        this.nodes = data.nodes || []; this.links = data.links || []; this.discoveredLinks = data.discovered_links || [];
        this.alerts = data.alert_summary || {}; this.history = data.history || []; this.discovery = data.discovery || {};
        this.snapshots = data.snapshots || []; this.replay = data.replay || null;
        this.placedEndpointIds = data.placed_endpoint_ids || [];
        this.lastUpdatedLabel = 'Updated just now';
        this.$nextTick(() => { this.attachCanvasInteractions(); this.renderCanvas(); if (!wanted) this.fitAll(); });
      } catch (error) {
        if (!silent) window.wardenToast(error.message || 'Could not load topology', 'error');
        this.lastUpdatedLabel = 'Refresh failed';
      } finally { this.loading = false; }
    },
    async selectFloor(id) {
      this.loading = true;
      try {
        const data = await wardenFetchJSON('/topology/state' + this.stateQuery(id));
        this.floors = data.floors || []; this.floor = data.floor; this.rooms = data.rooms || [];
        this.placements = data.placements || []; this.endpoints = data.endpoints || [];
        this.nodes = data.nodes || []; this.links = data.links || []; this.discoveredLinks = data.discovered_links || [];
        this.alerts = data.alert_summary || {}; this.history = data.history || []; this.discovery = data.discovery || {};
        this.snapshots = data.snapshots || []; this.replay = data.replay || null;
        this.placedEndpointIds = data.placed_endpoint_ids || []; this.selectedEndpointId = ''; this.selectedNodeId = '';
        this.lastUpdatedLabel = 'Updated just now';
        this.$nextTick(() => { this.attachCanvasInteractions(); this.renderCanvas(); this.fitAll(); });
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.loading = false; }
    },
    async createFloor() {
      if (this.saving) return; this.saving = true;
      try {
        const result = await wardenFetchJSON('/topology/floors', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify(this.floorForm),
        });
        this.showFloorModal = false; this.floorForm.name = '';
        this.branchId = result.floor.branch_id || '';
        window.history.replaceState(null, '', '/topology?branch_id=' + encodeURIComponent(this.branchId));
        await this.selectFloor(result.floor.id);
        window.wardenToast('Floor created', 'success');
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.saving = false; }
    },
    async createRoom() {
      if (!this.floor || !this.roomDraft || this.saving) return; this.saving = true;
      try {
        await wardenFetchJSON(`/topology/floors/${this.floor.id}/rooms`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ ...this.roomForm, x: this.roomDraft.x, y: this.roomDraft.y, width: this.roomDraft.width, height: this.roomDraft.height }),
        });
        this.showRoomModal = false; this.roomForm.name = ''; this.roomDraft = null; await this.refresh(true);
        window.wardenToast('Room added', 'success');
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.saving = false; }
    },
    openAssetModal() {
      if (!this.floor || this.floor.layout_locked) return;
      this.assetForm = { node_type: 'switch', name: '', ip_address: '', room_id: '', details: '' };
      this.showAssetModal = true;
      this.$nextTick(() => this.renderRoomOptions());
    },
    async createAsset() {
      if (!this.floor || !this.assetForm.name || this.saving) return;
      this.saving = true;
      const room = this.rooms.find(item => item.id === this.assetForm.room_id);
      const position = room
        ? { x: Number(room.x) + Number(room.width) / 2, y: Number(room.y) + Number(room.height) / 2 }
        : { x: 48 + (this.nodes.length % 4) * 3, y: 46 + (this.nodes.length % 3) * 4 };
      try {
        const result = await wardenFetchJSON(`/topology/floors/${this.floor.id}/nodes`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ ...this.assetForm, ...position }),
        });
        this.showAssetModal = false; await this.refresh(true); this.chooseTopologyObject('node', result.node.id);
        window.wardenToast('Asset placed on map', 'success');
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.saving = false; }
    },
    toggleConnecting() {
      this.connecting = !this.connecting; this.connectionStart = null; this.connectionTarget = null;
      this.renderCanvas();
    },
    startConnectFrom(type, id) {
      this.connecting = true; this.connectionStart = { type, id }; this.connectionTarget = null;
      this.renderCanvas();
    },
    chooseTopologyObject(type, id) {
      if (this.connecting) {
        if (!this.connectionStart) { this.connectionStart = { type, id }; this.renderCanvas(); return; }
        if (this.connectionStart.type === type && this.connectionStart.id === id) return;
        this.connectionTarget = { type, id }; this.showLinkModal = true;
        return;
      }
      this.selectedEndpointId = type === 'endpoint' ? id : '';
      this.selectedNodeId = type === 'node' ? id : '';
      this.selectedLinkId = '';
      this.renderCanvas();
    },
    closeInspector() {
      this.selectedEndpointId = '';
      this.selectedNodeId = '';
      this.selectedLinkId = '';
      this.renderCanvas();
    },
    setHeatmap(mode) { this.heatmap = mode; this.renderCanvas(); },
    setViewMode(mode) { this.viewMode = mode; this.renderCanvas(); },
    setOverlay(mode) { this.overlay = this.overlay === mode ? 'none' : mode; this.renderCanvas(); },
    async loadSnapshot(id) {
      if (!this.floor) return;
      if (!id) { this.replay = null; await this.refresh(); return; }
      this.loading = true;
      try {
        const data = await wardenFetchJSON('/topology/state' + this.stateQuery(this.floor.id, id));
        this.rooms = data.rooms || []; this.placements = data.placements || []; this.endpoints = data.endpoints || [];
        this.nodes = data.nodes || []; this.links = data.links || []; this.discoveredLinks = data.discovered_links || [];
        this.alerts = data.alert_summary || {}; this.history = data.history || []; this.snapshots = data.snapshots || [];
        this.placedEndpointIds = data.placed_endpoint_ids || []; this.replay = data.replay || null;
        this.$nextTick(() => this.renderCanvas());
      } catch (error) { window.wardenToast(error.message || 'Could not replay snapshot', 'error'); }
      finally { this.loading = false; }
    },
    applyMapFilters() { this.renderCanvas(); },
    floorBounds() {
      let left = 0, top = 0, right = 100, bottom = 100;
      this.rooms.forEach(room => {
        left = Math.min(left, Number(room.x)); top = Math.min(top, Number(room.y));
        right = Math.max(right, Number(room.x) + Number(room.width));
        bottom = Math.max(bottom, Number(room.y) + Number(room.height));
      });
      [...this.placements, ...this.nodes].forEach(point => {
        left = Math.min(left, Number(point.x) - 7); top = Math.min(top, Number(point.y) - 7);
        right = Math.max(right, Number(point.x) + 7); bottom = Math.max(bottom, Number(point.y) + 7);
      });
      return { left, top, width: right - left, height: bottom - top };
    },
    fitAll() {
      const bounds = this.floorBounds();
      this.canvasZoom = Math.min(1, 100 / (bounds.width + 10), 100 / (bounds.height + 10));
      this.canvasPanX = (bounds.left + bounds.width / 2) * 10 - 500;
      this.canvasPanY = (bounds.top + bounds.height / 2) * 6 - 300;
      this.updateCanvasView();
    },
    focusObject(key) {
      const [type, id] = String(key || '').split(':');
      if (!id) return;
      this.chooseTopologyObject(type, id);
      const point = this.linkPoint(type, id);
      this.canvasZoom = 1.45; this.canvasPanX = point.x - 500; this.canvasPanY = point.y - 300;
      this.constrainCanvasPan(); this.updateCanvasView();
    },
    pathKeys() {
      if (!this.pathStart || !this.pathEnd || this.pathStart === this.pathEnd) return new Set();
      const graph = new Map();
      this.allVisibleLinks.forEach(link => {
        const a = `${link.source_type}:${link.source_id}`; const b = `${link.target_type}:${link.target_id}`;
        if (!graph.has(a)) graph.set(a, []); if (!graph.has(b)) graph.set(b, []);
        graph.get(a).push([b, link.id]); graph.get(b).push([a, link.id]);
      });
      const queue = [this.pathStart]; const seen = new Set(queue); const previous = new Map();
      while (queue.length) {
        const current = queue.shift(); if (current === this.pathEnd) break;
        (graph.get(current) || []).forEach(([next, linkId]) => { if (!seen.has(next)) { seen.add(next); previous.set(next, [current, linkId]); queue.push(next); } });
      }
      const result = new Set(); let cursor = this.pathEnd;
      while (previous.has(cursor)) { const [prior, linkId] = previous.get(cursor); result.add(linkId); cursor = prior; }
      return cursor === this.pathStart ? result : new Set();
    },
    historyLabel(item) {
      const labels = { topology_endpoint_moved: 'Endpoint moved', topology_endpoint_unplaced: 'Endpoint removed', topology_floor_created: 'Floor created', topology_floor_updated: 'Floor updated', topology_floor_deleted: 'Floor deleted', topology_room_created: 'Room created', topology_asset_created: 'Asset added' };
      return labels[item.action] || String(item.action || 'Topology changed').replaceAll('_', ' ');
    },
    objectName(type, id) {
      if (type === 'endpoint') { const item = this.endpoints.find(value => value.id === id); return item ? (item.display_name || item.hostname) : 'Endpoint'; }
      const item = this.nodes.find(value => value.id === id); return item ? item.name : 'Asset';
    },
    selectLink(id) { this.selectedLinkId = id; this.selectedEndpointId = ''; this.selectedNodeId = ''; this.renderCanvas(); },
    cancelLink() {
      this.showLinkModal = false; this.connecting = false; this.connectionStart = null; this.connectionTarget = null;
      this.renderCanvas();
    },
    async createLink() {
      if (!this.floor || !this.connectionStart || !this.connectionTarget || this.saving) return;
      this.saving = true;
      try {
        await wardenFetchJSON(`/topology/floors/${this.floor.id}/links`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ source_type: this.connectionStart.type, source_id: this.connectionStart.id, target_type: this.connectionTarget.type, target_id: this.connectionTarget.id, ...this.linkForm }),
        });
        this.cancelLink(); this.linkForm = { link_type: 'ethernet', label: '' }; await this.refresh(true);
        window.wardenToast('Connection added', 'success');
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.saving = false; }
    },
    async toggleLock() {
      if (!this.floor || this.saving) return; this.saving = true;
      try {
        const result = await wardenFetchJSON(`/topology/floors/${this.floor.id}`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ layout_locked: !this.floor.layout_locked }),
        });
        this.floor = result.floor; this.floors = this.floors.map(item => item.id === this.floor.id ? this.floor : item);
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.saving = false; }
    },
    selectEndpoint(id) { this.selectedEndpointId = id; this.selectedNodeId = ''; this.renderCanvas(); },
    placementFor(id) { return this.placements.find(item => item.endpoint_id === id); },
    endpointTransform(endpoint) {
      const placement = endpoint.placement || this.placementFor(endpoint.id) || { x: 50, y: 50 };
      return `translate(${Number(placement.x) * 10 - 26} ${Number(placement.y) * 6 - 26})`;
    },
    beginEndpointDrag(event, id) {
      this.chooseTopologyObject('endpoint', id);
      if (this.connecting || this.drawingRoom || !this.canEdit || !this.floor || this.floor.layout_locked) return;
      event.preventDefault(); this.dragEndpointId = id; this.dragPointerId = event.pointerId;
      this.dragStartClientX = event.clientX; this.dragStartClientY = event.clientY; this.dragMoved = false;
      if (event.currentTarget.setPointerCapture) event.currentTarget.setPointerCapture(event.pointerId);
    },
    beginNodeDrag(event, id) {
      this.chooseTopologyObject('node', id);
      if (this.connecting || this.drawingRoom || !this.canEdit || !this.floor || this.floor.layout_locked) return;
      event.preventDefault(); this.dragNodeId = id; this.dragPointerId = event.pointerId;
      if (event.currentTarget.setPointerCapture) event.currentTarget.setPointerCapture(event.pointerId);
    },
    toggleRoomDrawing() {
      if (!this.canEdit || !this.floor || this.floor.layout_locked) return;
      this.drawingRoom = !this.drawingRoom;
      this.roomDraft = null; this.roomPointerId = null;
    },
    topologyPageClass() {
      const classes = [];
      if (this.focusMap) classes.push('is-focus-map');
      if (!this.showFloorRail) classes.push('is-floor-rail-hidden');
      return classes.join(' ');
    },
    canvasViewBox() {
      const width = 1000 / this.canvasZoom; const height = 600 / this.canvasZoom;
      return `${500 - width / 2 + this.canvasPanX} ${300 - height / 2 + this.canvasPanY} ${width} ${height}`;
    },
    canvasClass() {
      if (this.drawingRoom) return 'is-drawing-room';
      if (this.panPointerId !== null) return 'is-panning';
      return 'is-pan-ready';
    },
    attachCanvasInteractions() {
      const canvas = this.$refs.canvas;
      if (!canvas || canvas.dataset.interactionsAttached === '1') return;
      canvas.dataset.interactionsAttached = '1';
      this.updateCanvasView();
      canvas.addEventListener('pointerdown', event => this.beginCanvasPointer(event));
      canvas.addEventListener('pointermove', event => this.moveCanvasPointer(event));
      canvas.addEventListener('pointerup', event => this.endCanvasPointer(event));
      canvas.addEventListener('pointercancel', () => this.cancelCanvasPointer());
      canvas.addEventListener('wheel', event => {
        event.preventDefault();
        this.zoomCanvasWheel(event);
      }, { passive: false });
    },
    canvasZoomLabel() { return `${Math.round(this.canvasZoom * 100)}%`; },
    updateCanvasView() {
      if (this.$refs.canvas) this.$refs.canvas.setAttribute('viewBox', this.canvasViewBox());
      this.renderMinimap();
    },
    renderMinimap() {
      const roomsLayer = this.$refs.miniRoomsLayer;
      const endpointsLayer = this.$refs.miniEndpointsLayer;
      const viewport = this.$refs.miniViewport;
      if (!roomsLayer || !endpointsLayer || !viewport) return;
      const bounds = this.floorBounds();
      this.$refs.minimap.setAttribute('viewBox', `${bounds.left - 5} ${bounds.top - 5} ${bounds.width + 10} ${bounds.height + 10}`);
      roomsLayer.replaceChildren();
      endpointsLayer.replaceChildren();
      this.rooms.forEach(room => roomsLayer.append(this.svgElement('rect', {
        class: 'mini-room', x: room.x, y: room.y,
        width: room.width, height: room.height,
      })));
      this.visibleFloorEndpoints.forEach(endpoint => {
        const point = this.svgElement('circle', {
          class: endpoint.status === 'online' ? 'online' : 'offline',
          cx: endpoint.placement.x, cy: endpoint.placement.y, r: 2.2,
          role: 'button', tabindex: 0,
          'aria-label': endpoint.display_name || endpoint.hostname,
        });
        point.addEventListener('click', () => this.focusObject(`endpoint:${endpoint.id}`));
        point.addEventListener('keydown', event => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault(); this.focusObject(`endpoint:${endpoint.id}`);
          }
        });
        endpointsLayer.append(point);
      });
      viewport.setAttribute('width', String(100 / this.canvasZoom));
      viewport.setAttribute('height', String(100 / this.canvasZoom));
      viewport.setAttribute('x', String(50 - 50 / this.canvasZoom + this.canvasPanX / 10));
      viewport.setAttribute('y', String(50 - 50 / this.canvasZoom + this.canvasPanY / 6));
    },
    zoomCanvas(delta) {
      this.canvasZoom = Math.min(2, Math.max(0.005, this.canvasZoom * (delta > 0 ? 1.1 : 1 / 1.1)));
      this.constrainCanvasPan();
      this.updateCanvasView();
    },
    zoomCanvasWheel(event) { this.zoomCanvas(event.deltaY < 0 ? 0.1 : -0.1); },
    resetCanvasView() { this.fitAll(); },
    constrainCanvasPan() {
      this.canvasPanX = Math.max(-90000, Math.min(90000, this.canvasPanX));
      this.canvasPanY = Math.max(-54000, Math.min(54000, this.canvasPanY));
    },
    canvasPoint(event) {
      const svg = this.$refs.canvas; const matrix = svg.getScreenCTM();
      if (!matrix) return null;
      const point = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
      return { x: Math.max(-9000, Math.min(9000, point.x / 10)), y: Math.max(-9000, Math.min(9000, point.y / 6)) };
    },
    beginCanvasPointer(event) {
      const endpointTarget = event.target.closest('[data-endpoint-id]');
      if (endpointTarget) { this.beginEndpointDrag(event, endpointTarget.dataset.endpointId); return; }
      const nodeTarget = event.target.closest('[data-node-id]');
      if (nodeTarget) { this.beginNodeDrag(event, nodeTarget.dataset.nodeId); return; }
      if (this.drawingRoom) {
        if (!this.canEdit || !this.floor || this.floor.layout_locked || event.target.closest('.topology-device')) return;
        const point = this.canvasPoint(event);
        if (!point) return;
        event.preventDefault();
        this.roomPointerId = event.pointerId;
        this.roomDraft = { startX: point.x, startY: point.y, x: point.x, y: point.y, width: 0, height: 0 };
        this.updateRoomDraftElement();
        if (this.$refs.canvas.setPointerCapture) this.$refs.canvas.setPointerCapture(event.pointerId);
        return;
      }
      if (event.pointerType === 'mouse' && event.button !== 0) return;
      event.preventDefault();
      this.panPointerId = event.pointerId;
      this.panStartClientX = event.clientX; this.panStartClientY = event.clientY;
      this.panStartX = this.canvasPanX; this.panStartY = this.canvasPanY;
      this.panStartScale = this.$refs.canvas.getScreenCTM()?.a || 1;
      if (this.$refs.canvas.setPointerCapture) this.$refs.canvas.setPointerCapture(event.pointerId);
    },
    moveCanvasPointer(event) {
      if (this.panPointerId !== null && event.pointerId === this.panPointerId) {
        this.canvasPanX = this.panStartX - (event.clientX - this.panStartClientX) / this.panStartScale;
        this.canvasPanY = this.panStartY - (event.clientY - this.panStartClientY) / this.panStartScale;
        this.constrainCanvasPan();
        this.updateCanvasView();
        return;
      }
      if (this.roomDraft && event.pointerId === this.roomPointerId) {
        const point = this.canvasPoint(event);
        if (!point) return;
        this.roomDraft.x = Math.min(this.roomDraft.startX, point.x);
        this.roomDraft.y = Math.min(this.roomDraft.startY, point.y);
        this.roomDraft.width = Math.abs(point.x - this.roomDraft.startX);
        this.roomDraft.height = Math.abs(point.y - this.roomDraft.startY);
        this.updateRoomDraftElement();
        return;
      }
      if (this.dragNodeId && event.pointerId === this.dragPointerId) {
        const point = this.canvasPoint(event); const node = this.nodes.find(item => item.id === this.dragNodeId);
        if (point && node) {
          node.x = point.x; node.y = point.y; node.room_id = this.roomAt(node.x, node.y);
          const element = this.$refs.nodesLayer?.querySelector(`[data-node-id="${node.id}"]`);
          if (element) element.setAttribute('transform', this.nodeTransform(node));
          this.renderLinks();
        }
        return;
      }
      this.moveEndpoint(event);
    },
    async endCanvasPointer(event) {
      if (this.panPointerId !== null && event.pointerId === this.panPointerId) {
        this.panPointerId = null;
        return;
      }
      if (this.roomDraft && event.pointerId === this.roomPointerId) {
        this.roomPointerId = null; this.drawingRoom = false;
        if (this.roomDraft.width < 3 || this.roomDraft.height < 3) {
          this.roomDraft = null;
          this.updateRoomDraftElement();
          window.wardenToast('Draw a larger room area', 'warning');
          return;
        }
        this.roomDraft.x = Number(this.roomDraft.x.toFixed(3));
        this.roomDraft.y = Number(this.roomDraft.y.toFixed(3));
        this.roomDraft.width = Number(this.roomDraft.width.toFixed(3));
        this.roomDraft.height = Number(this.roomDraft.height.toFixed(3));
        this.showRoomModal = true;
        this.$nextTick(() => this.$refs.roomName?.focus());
        return;
      }
      if (this.dragNodeId && event.pointerId === this.dragPointerId) {
        const id = this.dragNodeId; const node = this.nodes.find(item => item.id === id);
        this.dragNodeId = ''; this.dragPointerId = null;
        if (node) await this.saveNodePosition(node);
        return;
      }
      await this.endEndpointDrag(event);
    },
    cancelCanvasPointer() {
      if (this.roomDraft && this.roomPointerId !== null) this.roomDraft = null;
      this.updateRoomDraftElement();
      this.roomPointerId = null;
      this.panPointerId = null;
      this.dragNodeId = '';
      this.cancelEndpointDrag();
    },
    cancelRoomDraft() {
      this.showRoomModal = false; this.roomDraft = null; this.roomForm.name = '';
      this.updateRoomDraftElement();
    },
    svgPoint(event) {
      return this.canvasPoint(event);
    },
    updateEndpointDragPosition(event) {
      if (!this.dragEndpointId || event.pointerId !== this.dragPointerId) return;
      const point = this.svgPoint(event); const placement = this.placementFor(this.dragEndpointId);
      if (point && placement) {
        placement.x = point.x; placement.y = point.y; placement.room_id = this.roomAt(point.x, point.y);
        const element = this.$refs.endpointsLayer?.querySelector(`[data-endpoint-id="${this.dragEndpointId}"]`);
        const endpoint = this.endpoints.find(item => item.id === this.dragEndpointId);
        if (element && endpoint) element.setAttribute('transform', this.endpointTransform({ ...endpoint, placement }));
        this.renderLinks();
      }
    },
    moveEndpoint(event) {
      if (!this.dragEndpointId || event.pointerId !== this.dragPointerId) return;
      if (!this.dragMoved) {
        const distance = Math.hypot(event.clientX - this.dragStartClientX, event.clientY - this.dragStartClientY);
        if (distance < 3) return;
        this.dragMoved = true;
      }
      this.updateEndpointDragPosition(event);
    },
    async endEndpointDrag(event) {
      if (!this.dragEndpointId || event.pointerId !== this.dragPointerId) return;
      if (this.dragMoved) this.updateEndpointDragPosition(event);
      const id = this.dragEndpointId; const placement = this.placementFor(id);
      const shouldSave = this.dragMoved;
      this.dragEndpointId = ''; this.dragPointerId = null; this.dragMoved = false;
      if (shouldSave && placement) await this.savePlacement(id, placement.x, placement.y, placement.room_id);
    },
    cancelEndpointDrag() { this.dragEndpointId = ''; this.dragPointerId = null; this.dragMoved = false; },
    startTrayDrag(event, id) { if (this.canEdit && this.floor && !this.floor.layout_locked) event.dataTransfer.setData('text/warden-endpoint', id); },
    async dropFromTray(event) {
      if (!this.canEdit || !this.floor || this.floor.layout_locked) return;
      const id = event.dataTransfer.getData('text/warden-endpoint'); const point = this.svgPoint(event);
      if (!id || !point) return;
      await this.savePlacement(id, point.x, point.y, this.roomAt(point.x, point.y)); this.selectedEndpointId = id; await this.refresh(true);
    },
    roomAt(x, y) {
      const room = this.rooms.find(item => x >= Number(item.x) && x <= Number(item.x) + Number(item.width) && y >= Number(item.y) && y <= Number(item.y) + Number(item.height));
      return room ? room.id : null;
    },
    async savePlacement(id, x, y, roomId) {
      try {
        await wardenFetchJSON(`/topology/placements/${id}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ floor_id: this.floor.id, room_id: roomId || null, x, y }),
        });
      } catch (error) { window.wardenToast(error.message || 'Could not save device position', 'error'); await this.refresh(true); }
    },
    async unplaceSelected() {
      if (!this.selectedEndpoint) return;
      try {
        await wardenFetchJSON(`/topology/placements/${this.selectedEndpoint.id}`, { method: 'DELETE', headers: { 'X-CSRFToken': getCsrfToken() } });
        this.selectedEndpointId = ''; await this.refresh(true); this.showDeviceDrawer = true;
        window.wardenToast('Endpoint moved to the device drawer', 'success');
      } catch (error) { window.wardenToast(error.message, 'error'); }
    },
    openRemote() { if (this.selectedEndpoint && this.selectedEndpoint.status === 'online') { this.remoteReason = ''; this.showRemoteModal = true; } },
    async startRemote() {
      if (!this.selectedEndpoint || !this.remoteReason || this.saving) return;
      const tab = window.open('about:blank', '_blank');
      if (!tab) { window.wardenToast('Allow pop-ups to open Remote Control', 'error'); return; }
      tab.document.title = 'Starting Warden Remote Control…';
      tab.document.body.textContent = 'Starting secure remote session…'; this.saving = true;
      try {
        const result = await wardenFetchJSON(`/endpoints/${this.selectedEndpoint.id}/start-session`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ access_mode: this.remoteMode, reason: this.remoteReason }),
        });
        if (!result.ok || !result.viewer_url) {
          throw new Error(result.message || result.error || 'Remote session failed');
        }
        this.showRemoteModal = false;
        tab.location.replace(result.viewer_url);
      } catch (error) {
        const message = error.message || 'Remote session failed';
        tab.document.title = 'Warden Remote Control unavailable';
        tab.document.body.textContent = `Could not start remote control: ${message}. Return to Warden to retry.`;
        window.wardenToast(message, 'error');
      } finally { this.saving = false; }
    },
    endpointNeedsAttention(endpoint) { return endpoint.status !== 'online' || Number(endpoint.cpu_pct || 0) >= 85 || Number(endpoint.ram_used_pct || 0) >= 90 || Number((this.alerts[endpoint.id] || {}).count || 0) > 0; },
    endpointClass(endpoint) {
      if (endpoint.status !== 'online') return 'is-offline';
      const value = this.heatmap === 'cpu' ? Number(endpoint.cpu_pct || 0) : this.heatmap === 'memory' ? Number(endpoint.ram_used_pct || 0) : 0;
      if (value >= 90 || (this.heatmap === 'status' && this.endpointNeedsAttention(endpoint))) return 'is-critical';
      if (value >= 70) return 'is-warning';
      return 'is-online';
    },
    roomX(room) { return Number(room.x) * 10; }, roomY(room) { return Number(room.y) * 6; },
    roomWidth(room) { return Number(room.width) * 10; }, roomHeight(room) { return Number(room.height) * 6; },
    roomOccupancy(room) { return this.placements.filter(item => item.room_id === room.id).length; },
    nodeTransform(node) {
      return `translate(${Number(node.x) * 10 - 47} ${Number(node.y) * 6 - 33})`;
    },
    async saveNodePosition(node) {
      try {
        await wardenFetchJSON(`/topology/nodes/${node.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() }, body: JSON.stringify({ x: node.x, y: node.y, room_id: node.room_id || null }) });
      } catch (error) { window.wardenToast(error.message || 'Could not move asset', 'error'); await this.refresh(true); }
    },
    linkPoint(type, id) {
      if (type === 'node') { const node = this.nodes.find(item => item.id === id); return node ? { x: Number(node.x) * 10, y: Number(node.y) * 6 } : { x: 0, y: 0 }; }
      const placement = this.placementFor(id); return placement ? { x: Number(placement.x) * 10, y: Number(placement.y) * 6 } : { x: 0, y: 0 };
    },
    linkMidpoint(link) { const a = this.linkPoint(link.source_type, link.source_id); const b = this.linkPoint(link.target_type, link.target_id); return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }; },
    connectionObjectClass(type, id) { return this.connectionStart && this.connectionStart.type === type && this.connectionStart.id === id ? 'is-connection-start' : ''; },
    nodeSymbol(type) { return ({ switch: '⇄', firewall: '▦', router: '↗', server: '▤', access_point: '⌁', printer: '▣', asset: '◇' })[type] || '◇'; },
    nodeTypeLabel(type) { return ({ switch: 'Network switch', firewall: 'Firewall', router: 'Router', server: 'Server', access_point: 'Access point', printer: 'Printer', asset: 'Asset' })[type] || 'Asset'; },
    linkTypeLabel(type) { return ({ ethernet: 'Ethernet', fiber: 'Fiber', wifi: 'Wi-Fi', vpn: 'VPN', logical: 'Logical' })[type] || 'Link'; },
    roomName(id) { const room = this.rooms.find(item => item.id === id); return room ? room.name : 'No room'; },
    nodeLinkCount(id) { return this.links.filter(link => (link.source_type === 'node' && link.source_id === id) || (link.target_type === 'node' && link.target_id === id)).length; },
    svgElement(tag, attributes = {}, content = null) {
      const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
      Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
      if (content !== null) element.textContent = String(content);
      return element;
    },
    shortLabel(value, limit = 20) {
      const text = String(value || ''); return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
    },
    deviceKind(endpoint) {
      if (['desktop', 'laptop', 'server', 'iot'].includes(endpoint.device_type)) return endpoint.device_type;
      const hints = [endpoint.os_name, endpoint.hostname, ...(Array.isArray(endpoint.tags) ? endpoint.tags : [])].join(' ').toLowerCase();
      if (/iot|embedded|raspberry|sensor|kiosk/.test(hints)) return 'iot';
      if (/server|windows server/.test(hints)) return 'server';
      if (/laptop|notebook|macbook|portable/.test(hints) || endpoint.platform === 'darwin') return 'laptop';
      return endpoint.platform === 'linux' ? 'server' : 'desktop';
    },
    platformGlyph(platform) { return platform === 'darwin' ? 'MAC' : platform === 'linux' ? 'LNX' : '⊞'; },
    appendDeviceOutline(group, endpoint) {
      const kind = this.deviceKind(endpoint); const glyph = this.platformGlyph(endpoint.platform);
      const icon = this.svgElement('g', { class: `device-outline is-${kind}`, transform: 'translate(5 5) scale(.8)' });
      if (kind === 'laptop') {
        icon.append(this.svgElement('rect', { class: 'device-screen', x: 9, y: 10, width: 34, height: 25, rx: 3 }));
        icon.append(this.svgElement('path', { d: 'M6 39h40l4 5H2z' }));
      } else if (kind === 'server') {
        icon.append(this.svgElement('rect', { class: 'device-server', x: 11, y: 7, width: 30, height: 40, rx: 4 }));
        icon.append(this.svgElement('line', { x1: 16, y1: 17, x2: 35, y2: 17 }));
        icon.append(this.svgElement('line', { x1: 16, y1: 27, x2: 35, y2: 27 }));
        icon.append(this.svgElement('circle', { class: 'device-led', cx: 35, cy: 37, r: 2 }));
      } else if (kind === 'iot') {
        icon.append(this.svgElement('rect', { class: 'device-iot', x: 11, y: 9, width: 30, height: 30, rx: 8 }));
        icon.append(this.svgElement('circle', { class: 'device-sensor', cx: 26, cy: 24, r: 6 }));
        icon.append(this.svgElement('path', { d: 'M16 6v4m10-4v4m10-4v4M16 38v4m10-4v4m10-4v4M8 15h4M8 24h4M8 33h4M40 15h4M40 24h4M40 33h4' }));
      } else {
        icon.append(this.svgElement('rect', { class: 'device-screen', x: 8, y: 8, width: 36, height: 27, rx: 3 }));
        icon.append(this.svgElement('path', { d: 'M22 35v6m-8 3h24' }));
      }
      if (endpoint.platform === 'windows') {
        const windowsMark = this.svgElement('g', { class: 'device-windows-mark' });
        windowsMark.append(this.svgElement('rect', { x: 21, y: 20, width: 4, height: 4, rx: .4 }));
        windowsMark.append(this.svgElement('rect', { x: 27, y: 20, width: 4, height: 4, rx: .4 }));
        windowsMark.append(this.svgElement('rect', { x: 21, y: 26, width: 4, height: 4, rx: .4 }));
        windowsMark.append(this.svgElement('rect', { x: 27, y: 26, width: 4, height: 4, rx: .4 }));
        icon.append(windowsMark);
      } else {
        icon.append(this.svgElement('text', { class: 'device-os-mark', x: 26, y: kind === 'server' ? 38 : 27, 'text-anchor': 'middle' }, glyph));
      }
      group.append(icon);
    },
    endpointTooltipTransform(endpoint) {
      const placement = endpoint.placement || this.placementFor(endpoint.id) || { x: 50 };
      return Number(placement.x) > 72 ? 'translate(-226 -10)' : 'translate(60 -10)';
    },
    renderCanvas() {
      const roomsLayer = this.$refs.roomsLayer; const endpointsLayer = this.$refs.endpointsLayer; const nodesLayer = this.$refs.nodesLayer;
      if (!roomsLayer || !endpointsLayer || !nodesLayer) return;
      roomsLayer.replaceChildren(); endpointsLayer.replaceChildren(); nodesLayer.replaceChildren();
      this.rooms.forEach(room => {
        const overCapacity = this.overlay === 'capacity' && room.capacity && this.roomOccupancy(room) > Number(room.capacity) ? ' is-over-capacity' : '';
        const group = this.svgElement('g', { class: `topology-room${overCapacity}`, 'data-room-id': room.id });
        group.append(this.svgElement('rect', { x: this.roomX(room), y: this.roomY(room), width: this.roomWidth(room), height: this.roomHeight(room), fill: room.color, rx: 18 }));
        group.append(this.svgElement('text', { x: this.roomX(room) + 18, y: this.roomY(room) + 30 }, this.shortLabel(room.name, 34)));
        const occupancy = `${this.roomOccupancy(room)}${room.capacity ? ` / ${room.capacity}` : ''} devices`;
        group.append(this.svgElement('text', { class: 'room-count', x: this.roomX(room) + 18, y: this.roomY(room) + 50 }, occupancy));
        roomsLayer.append(group);
      });
      this.visibleFloorEndpoints.forEach(endpoint => {
        const selectedClass = endpoint.id === this.selectedEndpointId ? 'is-selected' : '';
        const classes = `topology-device platform-${endpoint.platform || 'windows'} ${this.endpointClass(endpoint)} ${selectedClass} ${this.connectionObjectClass('endpoint', endpoint.id)}`.trim();
        const group = this.svgElement('g', { class: classes, transform: this.endpointTransform(endpoint), 'data-endpoint-id': endpoint.id, tabindex: '0', role: 'button', 'aria-label': `${endpoint.display_name || endpoint.hostname}, ${this.platformLabel(endpoint.platform)}, ${endpoint.status}` });
        group.append(this.svgElement('title', {}, `${endpoint.display_name || endpoint.hostname} · ${this.endpointAddressText(endpoint) || 'IP not reported'}`));
        group.append(this.svgElement('rect', { class: 'device-marker', width: 52, height: 52, rx: 15 }));
        group.append(this.svgElement('rect', { class: 'device-icon-plate', x: 4, y: 4, width: 44, height: 44, rx: 13 }));
        group.append(this.svgElement('circle', { class: 'device-status-halo', cx: 45, cy: 8, r: 7 }));
        group.append(this.svgElement('circle', { class: 'device-status', cx: 45, cy: 8, r: 3.2 }));
        const alert = this.alerts[endpoint.id];
        if (alert && alert.count) {
          group.append(this.svgElement('circle', { class: `device-alert is-${alert.severity}`, cx: 7, cy: 7, r: 7 }));
          group.append(this.svgElement('text', { class: 'device-alert-count', x: 7, y: 10, 'text-anchor': 'middle' }, Math.min(alert.count, 9)));
        }
        this.appendDeviceOutline(group, endpoint);
        const hover = this.svgElement('g', { class: 'device-hover-card', transform: this.endpointTooltipTransform(endpoint) });
        hover.append(this.svgElement('rect', { class: 'device-hover-surface', width: 218, height: 112, rx: 16 }));
        hover.append(this.svgElement('text', { class: 'device-hover-name', x: 14, y: 23 }, this.shortLabel(endpoint.display_name || endpoint.hostname, 27)));
        hover.append(this.svgElement('text', { class: 'device-hover-meta', x: 14, y: 39 }, `${this.platformLabel(endpoint.platform)} · ${this.deviceKind(endpoint)} · ${endpoint.status}`));
        hover.append(this.svgElement('line', { class: 'device-hover-divider', x1: 14, y1: 49, x2: 204, y2: 49 }));
        hover.append(this.svgElement('text', { class: 'device-hover-label', x: 14, y: 66 }, 'LAN IP'));
        hover.append(this.svgElement('text', { class: 'device-hover-value', x: 67, y: 66 }, this.shortLabel(this.endpointAddressSummary(endpoint), 22)));
        hover.append(this.svgElement('text', { class: 'device-hover-label', x: 14, y: 83 }, 'USER'));
        hover.append(this.svgElement('text', { class: 'device-hover-value', x: 67, y: 83 }, this.shortLabel(endpoint.interactive_user || endpoint.assigned_to || 'No active session', 22)));
        hover.append(this.svgElement('text', { class: 'device-hover-health', x: 14, y: 102 }, `CPU ${this.metric(endpoint.cpu_pct, '%')}  ·  RAM ${this.metric(endpoint.ram_used_pct, '%')}`));
        group.append(hover);
        group.addEventListener('pointerenter', () => endpointsLayer.append(group));
        endpointsLayer.append(group);
      });
      this.nodes.forEach(node => {
        const classes = `topology-node ${node.node_type} ${this.connectionObjectClass('node', node.id)}`.trim();
        const group = this.svgElement('g', { class: classes, transform: this.nodeTransform(node), 'data-node-id': node.id });
        group.append(this.svgElement('rect', { width: 94, height: 66, rx: 15 }));
        group.append(this.svgElement('text', { class: 'node-symbol', x: 47, y: 24, 'text-anchor': 'middle' }, this.nodeSymbol(node.node_type)));
        group.append(this.svgElement('text', { class: 'node-name', x: 47, y: 43, 'text-anchor': 'middle' }, this.shortLabel(node.name, 15)));
        group.append(this.svgElement('text', { class: 'node-ip', x: 47, y: 57, 'text-anchor': 'middle' }, this.shortLabel(node.ip_address || this.nodeTypeLabel(node.node_type), 19)));
        nodesLayer.append(group);
      });
      this.renderLinks(); this.updateRoomDraftElement();
      this.renderRoomOptions();
      this.renderMinimap();
    },
    renderLinks() {
      const layer = this.$refs.linksLayer;
      if (!layer) return;
      layer.replaceChildren();
      const path = this.pathKeys();
      this.allVisibleLinks.forEach(link => {
        const start = this.linkPoint(link.source_type, link.source_id); const end = this.linkPoint(link.target_type, link.target_id);
        if ((!start.x && !start.y) || (!end.x && !end.y)) return;
        const selected = this.selectedLinkId === link.id ? ' is-selected' : '';
        const highlighted = path.has(link.id) ? ' is-path' : '';
        const discovered = link.discovered ? ' is-discovered' : '';
        const group = this.svgElement('g', { class: `topology-link is-${link.link_type}${selected}${highlighted}${discovered}`, 'data-link-id': link.id, role: 'button', tabindex: '0' });
        group.append(this.svgElement('line', { x1: start.x, y1: start.y, x2: end.x, y2: end.y }));
        const middle = { x: (start.x + end.x) / 2, y: (start.y + end.y) / 2 };
        group.append(this.svgElement('text', { x: middle.x, y: middle.y - 7, 'text-anchor': 'middle' }, this.shortLabel(link.label || this.linkTypeLabel(link.link_type), 24)));
        group.addEventListener('click', event => { event.stopPropagation(); this.selectLink(link.id); });
        layer.append(group);
      });
    },
    updateRoomDraftElement() {
      const element = this.$refs.roomDraftElement;
      if (!element) return;
      if (!this.roomDraft) { element.setAttribute('visibility', 'hidden'); return; }
      element.setAttribute('visibility', 'visible');
      element.setAttribute('x', String(this.roomDraft.x * 10)); element.setAttribute('y', String(this.roomDraft.y * 6));
      element.setAttribute('width', String(this.roomDraft.width * 10)); element.setAttribute('height', String(this.roomDraft.height * 6));
    },
    renderRoomOptions() {
      const select = this.$refs.assetRoomSelect;
      if (!select) return;
      const selected = this.assetForm.room_id;
      select.replaceChildren(new Option('No room', ''));
      this.rooms.forEach(room => select.add(new Option(room.name, room.id)));
      select.value = selected;
    },
    platformLabel(platform) { return platform === 'darwin' ? 'macOS' : platform === 'linux' ? 'Linux' : 'Windows'; },
    metric(value, suffix) { return value === null || value === undefined ? '—' : `${Number(value).toFixed(1)}${suffix}`; },
    timeAgoLabel(value) { return value ? timeAgo(value) : 'Never'; },
  };
}

/* ── Admin users page (users/list.html) ── */
function usersListPage() {
  return {
    showCreate: false,
    email: '',
    full_name: '',
    role: 'technician',
    branch_id: '',
    password: '',
    confirm: '',
    error: '',
    creating: false,
    resetPasswordValue: '',
    showEdit: false,
    editId: '',
    editName: '',
    editEmail: '',
    editSelf: false,
    editCurrentPassword: '',
    editPhoto: null,
    editPhotoPreview: '',
    editRole: 'technician',
    editBranch: '',
    editError: '',
    async createUser() {
      if (this.creating) return;
      this.creating = true;
      this.error = '';
      const fd = new FormData();
      fd.append('email', this.email);
      fd.append('full_name', this.full_name);
      fd.append('role', this.role);
      fd.append('branch_id', this.branch_id);
      fd.append('password', this.password);
      fd.append('confirm_password', this.confirm);
      try {
        await wardenFetchJSON('/users/create', {
          method: 'POST', body: fd, headers: { 'X-CSRFToken': getCsrfToken() },
        });
        this.showCreate = false;
        window.location.reload();
      } catch (error) {
        this.error = error.message;
      } finally {
        this.creating = false;
      }
    },
    async sendWelcome(id) {
      if (!await window.wardenConfirm({ title: 'Send welcome email?', message: 'Send sign-in guidance to this administrator’s login email?', detail: 'No password will be included.', confirmLabel: 'Send welcome' })) return;
      try {
        const data = await wardenFetchJSON(`/users/${id}/welcome-email`, { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } });
        wardenToast(data.message, 'success');
      } catch (error) { wardenToast(error.message, 'error'); }
    },
    async sendResetLink(id) {
      if (!await window.wardenConfirm({ title: 'Email password reset link?', message: 'Send a single-use link to this administrator’s login email?', detail: 'The current password remains valid until the owner uses the link.', confirmLabel: 'Send link' })) return;
      try {
        const data = await wardenFetchJSON(`/users/${id}/reset-link`, { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } });
        wardenToast(data.message, 'success');
      } catch (error) { wardenToast(error.message, 'error'); }
    },
    async resetPassword(id, name) {
      if (!await window.wardenConfirm({
        title: 'Reset administrator password?',
        message: `Create a new password for ${name}?`,
        detail: 'Existing sessions will be revoked immediately. The generated password is shown only once.',
        tone: 'danger', confirmLabel: 'Reset password',
      })) return;
      try {
        const data = await wardenFetchJSON(`/users/${id}/reset-password`, { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } });
        this.resetPasswordValue = data.new_password || '';
      } catch (error) { wardenToast(error.message, 'error'); }
    },
    async copyResetPassword() {
      try { await navigator.clipboard.writeText(this.resetPasswordValue); wardenToast('Password copied', 'success'); }
      catch (_) { wardenToast('Copy failed; select the password manually', 'error'); }
    },
    openEdit(data) {
      this.editId = data.id;
      this.editName = data.name;
      this.editEmail = data.email;
      this.editSelf = data.self === '1';
      this.editCurrentPassword = '';
      this.editPhoto = null;
      this.editPhotoPreview = data.photo === '1' ? `/users/${data.id}/photo` : '';
      this.editRole = data.role;
      this.editBranch = data.branch || '';
      this.editError = '';
      this.showEdit = true;
    },
    async selectAdminPhoto(event) {
      try {
        this.editPhoto = await normalizeProfilePhoto(event.target.files[0]);
        this.editPhotoPreview = this.editPhoto;
      } catch (error) { this.editError = error.message; event.target.value = ''; }
    },
    removeAdminPhoto() { this.editPhoto = ''; this.editPhotoPreview = ''; },
    async saveEdit() {
      try {
        await wardenFetchJSON(`/users/${this.editId}/update`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ full_name: this.editName, email: this.editEmail,
            current_password: this.editCurrentPassword, role: this.editRole, branch_id: this.editBranch || null,
            ...(this.editPhoto !== null ? { profile_photo: this.editPhoto } : {}) }),
        });
        window.location.reload();
      } catch (error) { this.editError = error.message; }
    },
  };
}

function patchManagementPage() {
  return {
    busy: false,
    endpointIds: [],
    init() {
      try { this.endpointIds = JSON.parse(this.$el.dataset.endpointIds || '[]'); }
      catch (_) { this.endpointIds = []; }
    },
    async send(endpointIds, action) {
      if (this.busy) return;
      this.busy = true;
      try {
        const result = await wardenFetchJSON('/endpoints/bulk-dispatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ type: 'WINDOWS_UPDATE', payload: { action }, endpoint_ids: endpointIds }),
        });
        wardenToast(`${result.dispatched || 0} patch job(s) queued`, 'success');
      } catch (error) {
        wardenToast(error.message || 'Could not queue patch jobs', 'error');
      } finally {
        this.busy = false;
      }
    },
    async dispatch(action) {
      const verb = action === 'install' ? 'install pending updates on every Windows endpoint' : 'scan every Windows endpoint';
      if (!await window.wardenConfirm({
        title: action === 'install' ? 'Deploy Windows updates?' : 'Scan for Windows updates?',
        message: `Queue a job to ${verb}?`,
        detail: action === 'install' ? 'Installation can interrupt users or require a restart. Review the generated Jobs after dispatch.' : 'This reads update state and does not install updates.',
        confirmLabel: action === 'install' ? 'Queue installation' : 'Queue scan',
      })) return;
      return this.send(this.endpointIds, action);
    },
    scanEndpoint(endpointId) { return this.send([endpointId], 'check'); },
  };
}

function firewallPolicyPage() {
  return {
    installedApplications: [],
    deploymentEndpoints: [],
    editorOpen: false,
    editorTitle: 'Create firewall policy',
    editorError: '',
    saving: false,
    templateId: '',
    policyName: '',
    policyDescription: '',
    rules: [],
    deployOpen: false,
    deployTemplateId: '',
    deployName: '',
    deployBranchId: '',
    deployTargetMode: 'branch',
    deployEndpointIds: [],
    deployTag: '',
    deployReason: '',
    rolloutPercentage: 10,
    deployError: '',
    deployResult: '',
    deploying: false,
    init() {
      try {
        const values = JSON.parse(this.$el.dataset.installedApplications || '[]');
        this.installedApplications = Array.isArray(values) ? values : [];
      } catch (_) {
        this.installedApplications = [];
      }
      try {
        const endpoints = JSON.parse(this.$el.dataset.deploymentEndpoints || '[]');
        this.deploymentEndpoints = Array.isArray(endpoints) ? endpoints : [];
      } catch (_) {
        this.deploymentEndpoints = [];
      }
    },
    blankRule() {
      return {
        id: crypto.randomUUID(), name: '', enabled: true, direction: 'out',
        action: 'allow', priority: 0, protocol: 'tcp', program: '', inventoryPath: '', localPorts: '',
        remotePorts: '', remoteAddresses: '', profileDomain: true,
        profilePrivate: true, profilePublic: true,
      };
    },
    fromStoredRule(stored) {
      const profiles = Array.isArray(stored.profiles) ? stored.profiles.map(value => String(value).toLowerCase()) : [];
      const allProfiles = profiles.length === 0;
      return {
        id: crypto.randomUUID(), name: stored.name || '', enabled: stored.enabled !== false,
        direction: stored.direction || 'out', action: stored.action || 'allow', priority: Number(stored.priority || 0),
        protocol: stored.protocol || 'any', program: stored.program || '',
        inventoryPath: this.matchingInstalledPath(stored.program || ''),
        localPorts: (stored.local_ports || []).join(', '), remotePorts: (stored.remote_ports || []).join(', '),
        remoteAddresses: (stored.remote_addresses || []).join('\n'),
        profileDomain: allProfiles || profiles.includes('domain'),
        profilePrivate: allProfiles || profiles.includes('private'),
        profilePublic: allProfiles || profiles.includes('public'),
      };
    },
    parseRulesElement(element) {
      try {
        const stored = JSON.parse(element.dataset.rules || '[]');
        return stored.map(rule => this.fromStoredRule(rule));
      } catch (_) {
        wardenToast('This firewall policy could not be loaded.', 'error');
        return [];
      }
    },
    newPolicy() {
      this.templateId = '';
      this.policyName = '';
      this.policyDescription = '';
      this.rules = [this.blankRule()];
      this.editorTitle = 'Create firewall policy';
      this.editorError = '';
      this.editorOpen = true;
      document.body.style.overflow = 'hidden';
    },
    editPolicy(element) {
      const rules = this.parseRulesElement(element);
      if (!rules.length) return;
      this.templateId = element.dataset.templateId || '';
      this.policyName = element.dataset.templateName || '';
      this.policyDescription = element.dataset.templateDescription || '';
      this.rules = rules;
      this.editorTitle = 'Edit firewall policy';
      this.editorError = '';
      this.editorOpen = true;
      document.body.style.overflow = 'hidden';
    },
    clonePolicy(element) {
      const rules = this.parseRulesElement(element);
      if (!rules.length) return;
      this.templateId = '';
      this.policyName = `Copy of ${element.dataset.templateName || 'Firewall policy'}`;
      this.policyDescription = element.dataset.templateDescription || '';
      this.rules = rules;
      this.editorTitle = 'Clone and modify firewall policy';
      this.editorError = '';
      this.editorOpen = true;
      document.body.style.overflow = 'hidden';
    },
    useStarter(name) {
      this.newPolicy();
      if (name === 'public_network') {
        this.policyName = 'Public network protection';
        this.policyDescription = 'Blocks common Windows administrative services on the Public profile.';
        this.rules = [
          { ...this.blankRule(), name: 'Block inbound SMB and RPC on Public', direction: 'in', action: 'block', protocol: 'tcp', localPorts: '135, 139, 445', profileDomain: false, profilePrivate: false, profilePublic: true },
          { ...this.blankRule(), name: 'Block inbound RDP on Public', direction: 'in', action: 'block', protocol: 'tcp', localPorts: '3389', profileDomain: false, profilePrivate: false, profilePublic: true },
        ];
      } else if (name === 'lateral_movement') {
        this.policyName = 'Lateral movement controls';
        this.policyDescription = 'Restricts common SMB, RPC and RDP paths. Review against business requirements before deployment.';
        this.rules = [
          { ...this.blankRule(), name: 'Block outbound SMB', direction: 'out', action: 'block', protocol: 'tcp', remotePorts: '445' },
          { ...this.blankRule(), name: 'Block inbound SMB and RPC', direction: 'in', action: 'block', protocol: 'tcp', localPorts: '135, 139, 445' },
          { ...this.blankRule(), name: 'Block outbound RDP', direction: 'out', action: 'block', protocol: 'tcp', remotePorts: '3389' },
        ];
      }
    },
    closeEditor() {
      if (this.saving) return;
      this.editorOpen = false;
      document.body.style.overflow = '';
    },
    addRule() { this.rules.push(this.blankRule()); },
    removeRule(index) { if (this.rules.length > 1) this.rules.splice(index, 1); },
    moveRuleUp(index) {
      if (index <= 0) return;
      const previous = this.rules[index - 1];
      this.rules[index - 1] = this.rules[index];
      this.rules[index] = previous;
    },
    moveRuleDown(index) {
      if (index >= this.rules.length - 1) return;
      const next = this.rules[index + 1];
      this.rules[index + 1] = this.rules[index];
      this.rules[index] = next;
    },
    splitValues(value) {
      return String(value || '').split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
    },
    matchingInstalledPath(path) {
      const wanted = String(path || '').toLowerCase();
      const match = this.installedApplications.find(application => String(application.path || '').toLowerCase() === wanted);
      return match ? match.path : '';
    },
    selectInstalledApplication(rule) {
      if (rule.inventoryPath) rule.program = rule.inventoryPath;
    },
    installedApplicationLabel(application) {
      const endpoints = Array.isArray(application.endpoints) ? application.endpoints : [];
      const location = endpoints.length > 2
        ? `${endpoints.slice(0, 2).join(', ')} +${endpoints.length - 2}`
        : endpoints.join(', ');
      const version = application.version ? ` ${application.version}` : '';
      return `${application.name}${version}${location ? ` — ${location}` : ''}`;
    },
    serialiseRule(rule) {
      const profiles = [];
      if (rule.profileDomain) profiles.push('domain');
      if (rule.profilePrivate) profiles.push('private');
      if (rule.profilePublic) profiles.push('public');
      return {
        name: rule.name, enabled: Boolean(rule.enabled), direction: rule.direction, priority: Number(rule.priority || 0),
        action: rule.action, protocol: rule.protocol, program: rule.program,
        local_ports: this.splitValues(rule.localPorts), remote_ports: this.splitValues(rule.remotePorts),
        remote_addresses: this.splitValues(rule.remoteAddresses), profiles,
      };
    },
    async savePolicy() {
      if (this.saving) return;
      this.editorError = '';
      if (!this.policyName) { this.editorError = 'Enter a policy name.'; return; }
      if (!this.rules.length || this.rules.some(rule => !rule.name)) { this.editorError = 'Every rule needs a name.'; return; }
      if (this.rules.some(rule => !rule.profileDomain && !rule.profilePrivate && !rule.profilePublic)) { this.editorError = 'Select at least one profile for every rule.'; return; }
      if (this.rules.some(rule => rule.direction === 'out' && rule.action === 'block' && !rule.program)) { this.editorError = 'Outbound block rules must select an application so the Warden agent stays connected.'; return; }
      if (this.rules.some(rule => rule.direction === 'out' && rule.action === 'block' && /(^|[\\/])warden-agent\.exe$/i.test(rule.program))) { this.editorError = 'The Warden agent cannot be selected for an outbound block rule.'; return; }
      this.saving = true;
      try {
        await wardenFetchJSON('/settings/firewall-policies/save', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ template_id: this.templateId || null, name: this.policyName, description: this.policyDescription, rules: this.rules.map(rule => this.serialiseRule(rule)) }),
        });
        wardenToast('Firewall policy saved', 'success');
        window.location.reload();
      } catch (error) {
        this.editorError = error.message || 'Could not save firewall policy.';
        this.saving = false;
      }
    },
    openDeploy(element) {
      this.deployTemplateId = element.dataset.templateId || '';
      this.deployName = element.dataset.templateName || '';
      this.deployBranchId = '';
      this.deployTargetMode = 'branch';
      this.deployEndpointIds = [];
      this.deployTag = '';
      this.deployReason = '';
      this.rolloutPercentage = 10;
      this.deployError = '';
      this.deployResult = '';
      this.deployOpen = true;
      document.body.style.overflow = 'hidden';
    },
    onDeployTargetModeChange() {
      this.deployTag = '';
      this.deployEndpointIds = [];
    },
    onDeployBranchChange() {
      const available = new Set(this.deployEndpointOptions().map(endpoint => endpoint.id));
      this.deployEndpointIds = this.deployEndpointIds.filter(id => available.has(id));
    },
    deployEndpointOptions() {
      if (!this.deployBranchId) return [];
      return this.deploymentEndpoints.filter(endpoint =>
        endpoint.branch_id === this.deployBranchId && endpoint.platform === 'windows'
      );
    },
    toggleDeployEndpoint(endpointId) {
      const index = this.deployEndpointIds.indexOf(endpointId);
      if (index === -1) this.deployEndpointIds.push(endpointId);
      else this.deployEndpointIds.splice(index, 1);
    },
    deployEligibleCount() {
      const endpoints = this.deployEndpointOptions();
      if (this.deployTargetMode === 'endpoints') {
        return endpoints.filter(endpoint => this.deployEndpointIds.includes(endpoint.id)).length;
      }
      if (this.deployTargetMode === 'tag') {
        const wanted = this.deployTag.toLowerCase();
        if (!wanted) return 0;
        return endpoints.filter(endpoint => (endpoint.tags || []).some(tag => String(tag).toLowerCase() === wanted)).length;
      }
      return endpoints.length;
    },
    deployTargetCount() {
      const eligible = this.deployEligibleCount();
      return eligible ? Math.max(1, Math.ceil(eligible * Number(this.rolloutPercentage) / 100)) : 0;
    },
    canDeployPolicy() {
      return !this.deploying && Boolean(this.deployBranchId) && this.deployEligibleCount() > 0;
    },
    closeDeploy() {
      if (this.deploying) return;
      this.deployOpen = false;
      document.body.style.overflow = '';
    },
    async deployPolicy() {
      if (!this.canDeployPolicy()) return;
      this.deploying = true;
      this.deployError = '';
      try {
        const result = await wardenFetchJSON(`/settings/policy-templates/${encodeURIComponent(this.deployTemplateId)}/deploy`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            branch_id: this.deployBranchId,
            platform: 'windows',
            tag: this.deployTargetMode === 'tag' ? this.deployTag : '',
            include_endpoint_ids: this.deployTargetMode === 'endpoints' ? this.deployEndpointIds : [],
            rollout_percentage: Number(this.rolloutPercentage),
            reason: this.deployReason,
            idempotency_key: crypto.randomUUID(),
          }),
        });
        this.deployResult = `${result.queued} endpoint${result.queued === 1 ? '' : 's'} queued.`;
        wardenToast(this.deployResult, 'success');
      } catch (error) {
        this.deployError = error.message || 'Could not deploy firewall policy.';
      } finally {
        this.deploying = false;
      }
    },
  };
}

/* ── Central directory account assignment ──────────────────────────────── */
function normalizeProfilePhoto(file) {
  if (!file) return Promise.resolve('');
  if (!file.type.startsWith('image/') || file.size > 5 * 1024 * 1024) {
    return Promise.reject(new Error('Choose an image smaller than 5 MB.'));
  }
  return new Promise((resolve, reject) => {
    const image = new Image();
    const objectUrl = URL.createObjectURL(file);
    image.onload = () => {
      try {
        const side = Math.min(image.naturalWidth, image.naturalHeight);
        if (!side) throw new Error('The selected image is empty.');
        const canvas = document.createElement('canvas');
        canvas.width = 256;
        canvas.height = 256;
        const context = canvas.getContext('2d', { alpha: false });
        context.drawImage(
          image,
          (image.naturalWidth - side) / 2,
          (image.naturalHeight - side) / 2,
          side,
          side,
          0,
          0,
          256,
          256,
        );
        const result = canvas.toDataURL('image/png');
        if (result.length > 700000) throw new Error('The normalized picture is too large.');
        resolve(result);
      } catch (error) {
        reject(error);
      } finally {
        URL.revokeObjectURL(objectUrl);
      }
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error('The selected image could not be read.'));
    };
    image.src = objectUrl;
  });
}

function directoryPage() {
  return {
    wardenModalOpen: false,
    wardenMode: 'create',
    wardenIdentityId: '',
    wardenUsername: '',
    wardenLoginEmail: '',
    wardenDisplayName: '',
    wardenSetupUrl: '',
    wardenIsAdmin: false,
    wardenProfilePhoto: '',
    wardenProfilePreview: '',
    wardenEndpointIds: [],
    wardenSubmitting: false,
    wardenError: '',
    securityModalOpen: false,
    securityIdentityId: '',
    securityUsername: '',
    securityOfflineHours: 24,
    securityStartHour: '',
    securityEndHour: '',
    securityRequireCompliant: false,
    securitySubmitting: false,
    securityError: '',
    modalOpen: false,
    editing: false,
    username: '',
    fullName: '',
    profilePhoto: '',
    profilePreview: '',
    isAdmin: false,
    rotatePasswords: false,
    deleteUnselected: true,
    selectedEndpointIds: [],
    oneTimeCredentials: [],
    submitting: false,
    completed: false,
    error: '',

    openWardenIdentity() {
      this.wardenMode = 'create';
      this.wardenIdentityId = '';
      this.wardenUsername = '';
      this.wardenLoginEmail = '';
      this.wardenDisplayName = '';
      this.wardenIsAdmin = false;
      this.wardenProfilePhoto = '';
      this.wardenProfilePreview = '';
      this.wardenEndpointIds = [];
      this.wardenError = '';
      this.wardenSetupUrl = '';
      this.wardenModalOpen = true;
    },
    openWardenPassword(id, username) {
      this.wardenMode = 'password';
      this.wardenIdentityId = id;
      this.wardenUsername = username;
      this.wardenError = '';
      this.wardenSetupUrl = '';
      this.wardenModalOpen = true;
    },
    openWardenProfile(data) {
      this.wardenMode = 'edit';
      this.wardenIdentityId = data.id;
      this.wardenLoginEmail = data.email || '';
      this.wardenDisplayName = data.name || '';
      this.wardenProfilePhoto = null;
      this.wardenProfilePreview = data.photo === '1' ? `/directory/identities/${data.id}/photo` : '';
      this.wardenError = '';
      this.wardenSetupUrl = '';
      this.wardenModalOpen = true;
    },
    removeWardenPhoto() { this.wardenProfilePhoto = ''; this.wardenProfilePreview = ''; },
    openWardenAssign(id, username, endpoints) {
      this.wardenMode = 'assign';
      this.wardenIdentityId = id;
      this.wardenUsername = username;
      this.wardenEndpointIds = (endpoints || '').split(',').filter(Boolean);
      this.wardenError = '';
      this.wardenSetupUrl = '';
      this.wardenModalOpen = true;
    },
    closeWarden() {
      if (!this.wardenSubmitting) this.wardenModalOpen = false;
    },
    selectAllWarden() {
      this.wardenEndpointIds = Array.from(
        this.$root.querySelectorAll('.warden-endpoint-option input[type=checkbox]')
      ).map((input) => input.value);
    },
    async selectWardenProfilePhoto(event) {
      try {
        this.wardenProfilePhoto = await normalizeProfilePhoto(event.target.files[0]);
        this.wardenProfilePreview = this.wardenProfilePhoto;
        this.wardenError = '';
      } catch (error) {
        if (this.wardenMode !== 'edit') {
          this.wardenProfilePhoto = '';
          this.wardenProfilePreview = '';
        }
        this.wardenError = error.message;
        event.target.value = '';
      }
    },
    async submitWarden() {
      if (this.wardenSubmitting) return;
      this.wardenError = '';
      if (this.wardenMode === 'create' && (!this.wardenLoginEmail || !this.wardenDisplayName || !this.wardenEndpointIds.length)) return;
      this.wardenSubmitting = true;
      try {
        const creating = this.wardenMode === 'create';
        const assigning = this.wardenMode === 'assign';
        const editing = this.wardenMode === 'edit';
        const url = creating ? '/directory/identities' : (editing ? `/directory/identities/${this.wardenIdentityId}/profile` : (assigning ? `/directory/identities/${this.wardenIdentityId}/assignments` : `/directory/identities/${this.wardenIdentityId}/password`));
        const body = creating ? {
          login_email: this.wardenLoginEmail,
          display_name: this.wardenDisplayName,
          endpoint_ids: this.wardenEndpointIds,
          is_admin: this.wardenIsAdmin,
          profile_photo: this.wardenProfilePhoto,
        } : (editing ? { login_email: this.wardenLoginEmail, display_name: this.wardenDisplayName,
          ...(this.wardenProfilePhoto !== null ? { profile_photo: this.wardenProfilePhoto } : {}) }
          : (assigning ? { endpoint_ids: this.wardenEndpointIds } : {}));
        const result = await wardenFetchJSON(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify(body),
        });
        window.wardenToast(result.message || 'Warden identity updated', 'success');
        if (result.setup_url) {
          this.wardenSetupUrl = result.setup_url;
        } else {
          this.wardenModalOpen = false;
          window.location.reload();
        }
      } catch (error) {
        this.wardenError = error.message || 'Could not update Warden identity.';
      } finally {
        this.wardenSubmitting = false;
      }
    },
    async repairWardenIdentity(id, username) {
      if (!await window.wardenConfirm({
        title: 'Repair Warden sign-in?',
        message: `Rotate the device-only Windows credential for ${username} on assigned PCs.`,
        detail: 'Use this after an agent reinstall or when central verification succeeds but Windows rejects the sign-in. The user’s Warden password does not change.',
        confirmLabel: 'Queue repair',
      })) return;
      try {
        const result = await wardenFetchJSON(`/directory/identities/${id}/repair`, {
          method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() },
        });
        window.wardenToast(result.message || 'Identity repair queued', 'success');
        window.location.reload();
      } catch (error) {
        window.wardenToast(error.message || 'Could not repair identity', 'error');
      }
    },
    async copyWardenSetupUrl() {
      if (!this.wardenSetupUrl) return;
      await navigator.clipboard.writeText(this.wardenSetupUrl);
      window.wardenToast('Setup link copied', 'success');
    },
    async setWardenState(id, enabled) {
      const verb = enabled ? 'enable' : 'disable';
      if (!await window.wardenConfirm({
        title: `${enabled ? 'Enable' : 'Disable'} Warden identity?`,
        message: `This will ${verb} the identity on every assigned endpoint.`,
        detail: enabled ? 'The user will regain sign-in access after online endpoints apply the queued job.' : 'The user will be blocked from Warden sign-in. Local account deletion is a separate action.',
        tone: enabled ? 'warning' : 'danger', confirmLabel: enabled ? 'Enable identity' : 'Disable identity',
      })) return;
      try {
        const result = await wardenFetchJSON(`/directory/identities/${id}/state`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ enabled }),
        });
        window.wardenToast(result.message || `Identity ${verb} queued`, 'success');
        window.location.reload();
      } catch (error) {
        window.wardenToast(error.message || `Could not ${verb} identity.`, 'error');
      }
    },
    openWardenSecurity(data) {
      this.securityIdentityId = data.identityId || '';
      this.securityUsername = data.username || '';
      this.securityOfflineHours = Number.parseInt(data.offlineHours || '24', 10);
      this.securityStartHour = data.startHour || '';
      this.securityEndHour = data.endHour || '';
      this.securityRequireCompliant = data.requireCompliant === '1';
      this.securityError = '';
      this.securityModalOpen = true;
    },
    async submitWardenSecurity() {
      if (this.securitySubmitting) return;
      this.securitySubmitting = true;
      this.securityError = '';
      const hasHours = this.securityStartHour !== '' || this.securityEndHour !== '';
      try {
        const result = await wardenFetchJSON(`/directory/identities/${this.securityIdentityId}/security`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            offline_access_hours: Number(this.securityOfflineHours),
            utc_start_hour: hasHours ? Number(this.securityStartHour) : null,
            utc_end_hour: hasHours ? Number(this.securityEndHour) : null,
            require_compliant: this.securityRequireCompliant,
          }),
        });
        window.wardenToast(result.message || 'Security policy updated', 'success');
        this.securityModalOpen = false;
        window.location.reload();
      } catch (error) {
        this.securityError = error.message || 'Could not update security policy.';
      } finally {
        this.securitySubmitting = false;
      }
    },

    reset() {
      this.username = '';
      this.fullName = '';
      this.profilePhoto = '';
      this.profilePreview = '';
      this.isAdmin = false;
      this.rotatePasswords = false;
      this.deleteUnselected = true;
      this.selectedEndpointIds = [];
      this.oneTimeCredentials = [];
      this.submitting = false;
      this.completed = false;
      this.error = '';
    },
    openNew() {
      this.reset();
      this.editing = false;
      this.modalOpen = true;
    },
    openAssign(data) {
      this.reset();
      this.editing = true;
      this.username = data.username || '';
      this.fullName = data.fullName || '';
      this.isAdmin = data.isAdmin === '1';
      this.selectedEndpointIds = (data.endpoints || '').split(',').filter(Boolean);
      this.modalOpen = true;
    },
    close() {
      if (this.submitting) return;
      this.modalOpen = false;
      if (this.completed) window.location.reload();
    },
    selectAll() {
      this.selectedEndpointIds = Array.from(
        this.$root.querySelectorAll('.directory-endpoint-option input[type=checkbox]')
      ).map((input) => input.value);
    },
    async selectProfilePhoto(event) {
      try {
        this.profilePhoto = await normalizeProfilePhoto(event.target.files[0]);
        this.profilePreview = this.profilePhoto;
        this.error = '';
      } catch (error) {
        this.profilePhoto = '';
        this.profilePreview = '';
        this.error = error.message;
        event.target.value = '';
      }
    },
    async copyCredentials() {
      const text = this.oneTimeCredentials
        .map(item => `${item.hostname}\t${item.username}\t${item.password}`)
        .join('\n');
      await navigator.clipboard.writeText(text);
      window.wardenToast('One-time credentials copied', 'success');
    },
    async submit() {
      if (this.submitting || !this.username || !this.selectedEndpointIds.length) return;
      this.submitting = true;
      this.error = '';
      try {
        const result = await wardenFetchJSON('/directory/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            username: this.username,
            full_name: this.fullName,
            profile_photo: this.profilePhoto,
            endpoint_ids: this.selectedEndpointIds,
            is_admin: this.isAdmin,
            rotate_passwords: this.editing && this.rotatePasswords,
            delete_unselected: this.editing && this.deleteUnselected,
          }),
        });
        this.completed = true;
        this.oneTimeCredentials = result.one_time_credentials || [];
        window.wardenToast(result.message || 'Account assignment queued', 'success');
      } catch (error) {
        this.error = error.message || 'Could not queue account assignment.';
      } finally {
        this.submitting = false;
      }
    },
  };
}

/* ── Escalation card (partials/escalation_card.html) ──
   reqId comes from data-req-id — same reason every other component here
   reads its per-instance values off $el instead of constructor args. */
function escalationCard() {
  return {
    savePolicy: false,
    scope: 'this_user_this_endpoint',
    validDays: 30,
    note: '',
    reqId: '',
    submitting: false,
    init() {
      this.reqId = this.$el.dataset.reqId || '';
    },
    async approve() {
      if (this.submitting) return;
      this.submitting = true;
      const fd = new FormData();
      fd.append('save_policy', this.savePolicy ? '1' : '0');
      if (this.savePolicy) {
        fd.append('scope', this.scope);
        fd.append('valid_days', this.validDays);
        fd.append('note', this.note);
      }
      try {
        const r = await fetch(`/escalations/${this.reqId}/approve`, {
          method: 'POST', body: fd,
          headers: { 'HX-Request': 'true', 'X-CSRFToken': getCsrfToken() },
        });
        if (!r.ok) throw new Error((await r.text()) || 'Approval failed');
        const html = await r.text();
        const card = document.getElementById(`esc-${this.reqId}`);
        if (card) card.outerHTML = html;
      } catch (error) {
        window.wardenToast(error.message || 'Approval failed', 'error');
        this.submitting = false;
      }
    },
    async deny() {
      if (this.submitting) return;
      this.submitting = true;
      try {
        const r = await fetch(`/escalations/${this.reqId}/deny`, {
          method: 'POST',
          headers: { 'HX-Request': 'true', 'X-CSRFToken': getCsrfToken() },
        });
        if (!r.ok) throw new Error((await r.text()) || 'Denial failed');
        const html = await r.text();
        const card = document.getElementById(`esc-${this.reqId}`);
        if (card) card.outerHTML = html;
      } catch (error) {
        window.wardenToast(error.message || 'Denial failed', 'error');
        this.submitting = false;
      }
    },
  };
}

/* ── Endpoints list page (endpoints/list.html) ──
   Covers both the generate-installer modal and the bulk-action modal —
   one Alpine component per page, kept as a single x-data scope. */
function installerModal() {
  return {
    selectedEndpointIds: [],
    bulkTargetMode: 'selected',
    bulkReviewed: false,
    bulkReviewTargets: [],
    get selectionLabel() { return this.selectedEndpointIds.length + ' device(s) selected on this page'; },
    get bulkDispatchLabel() { return this.bulkReviewed ? 'Confirm dispatch' : 'Review recipients'; },
    get bulkReviewSummary() {
      const supported = this.bulkReviewTargets.filter(ep => ep.supported);
      return supported.length + ' supported · ' + supported.filter(ep => !ep.online).length + ' offline · ' + (this.bulkReviewTargets.length - supported.length) + ' unsupported (skipped)';
    },
    init() {
      this.bulkBranchId = this.$el.dataset.branch || '';
      this.selectedBranch = this.bulkBranchId;
    },
    toggleEndpoint(event) {
      const id = event.target.value;
      this.selectedEndpointIds = event.target.checked
        ? [...new Set([...this.selectedEndpointIds, id])]
        : this.selectedEndpointIds.filter(value => value !== id);
      this.clearBulkReview();
    },
    isEndpointSelected(id) { return this.selectedEndpointIds.includes(id); },
    selectPage() {
      this.selectedEndpointIds = Array.from(document.querySelectorAll('.fleet-device-check')).map(input => input.value);
      this.clearBulkReview();
    },
    clearSelection() { this.selectedEndpointIds = []; this.clearBulkReview(); },
    clearBulkReview() { this.bulkReviewed = false; this.bulkReviewTargets = []; },
    async reviewOrDispatchBulk() {
      if (this.bulkDispatching) return;
      if (this.bulkReviewed) return this.dispatchBulk();
      this.bulkDispatching = true;
      try {
        const selected = this.bulkTargetMode === 'selected';
        if (selected && !this.selectedEndpointIds.length) throw new Error('Select at least one device.');
        const preview = await wardenFetchJSON('/endpoints/bulk-dispatch', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ type: this.bulkJobType, preview: true, target_mode: this.bulkTargetMode,
            branch_id: this.bulkBranchId || null,
            target_mode: 'selected', endpoint_ids: this.bulkReviewTargets.map(ep => ep.id), endpoint_ids: selected ? this.selectedEndpointIds : [] }),
        });
        this.bulkReviewTargets = preview.targets || [];
        if (!this.bulkReviewTargets.some(ep => ep.supported)) throw new Error('No supported devices in this audience.');
        const list = this.$refs.bulkReviewList;
        list.replaceChildren();
        this.bulkReviewTargets.forEach(ep => {
          const item = document.createElement('li');
          item.textContent = ep.name + ' — ' + (ep.supported ? (ep.online ? 'Online' : 'Offline; will queue') : 'Unsupported; skipped');
          list.append(item);
        });
        this.bulkReviewed = true;
      } catch (error) { this.bulkResult = { error: error.message }; }
      finally { this.bulkDispatching = false; }
    },
    showGenerateModal: false,
    selectedBranch: '',
    selectedPlatform: 'windows-amd64',
    generating: false,
    buildResult: null,
    async generateInstaller() {
      if (this.generating) return;
      this.generating = true;
      const fd = new FormData();
      fd.append('branch_id', this.selectedBranch);
      fd.append('target_platform', this.selectedPlatform);
      try {
        this.buildResult = await wardenFetchJSON('/endpoints/generate-installer', {
          method: 'POST', body: fd, headers: { 'X-CSRFToken': getCsrfToken() },
        });
      } catch (error) {
        this.buildResult = { error: error.message };
      } finally {
        this.generating = false;
      }
    },
    close() {
      this.showGenerateModal = false;
      this.buildResult = null;
      this.selectedBranch = '';
      this.selectedPlatform = 'windows-amd64';
    },
    // Bulk action modal
    showBulkModal: false,
    bulkJobType: 'COLLECT_SYSINFO',
    bulkBranchId: '',
    bulkPayload: {},
    bulkDispatching: false,
    bulkResult: null,
    bulkWallpaperName: '',
    bulkLockScreenName: '',
    openBulkModal() {
      this.bulkJobType = 'COLLECT_SYSINFO';
      this.bulkBranchId = this.$el.dataset.branch || '';
      this.bulkTargetMode = this.selectedEndpointIds.length ? 'selected' : 'branch';
      this.clearBulkReview();
      this.bulkPayload = {};
      this.bulkResult = null;
      this.bulkWallpaperName = '';
      this.bulkLockScreenName = '';
      this.showBulkModal = true;
      document.body.classList.add('fleet-dialog-open');
    },
    onBulkTypeChange() {
      this.clearBulkReview();
      const defaults = {
        GET_EVENT_LOGS: { log_name: 'System' },
        WINDOWS_UPDATE: { action: 'check' },
        SET_PERIPHERAL_POLICY: { policy_type: 'block_usb_storage' },
        APPLY_DEVICE_EXPERIENCE: { image_fit: 'fill', announcement_title: '', announcement_message: '', announcement_severity: 'info', announcement_require_ack: false },
      };
      this.bulkPayload = defaults[this.bulkJobType] ? { ...defaults[this.bulkJobType] } : {};
    },
    closeBulk() {
      this.showBulkModal = false;
      this.bulkResult = null;
      this.bulkWallpaperName = '';
      this.bulkLockScreenName = '';
      document.body.classList.remove('fleet-dialog-open');
    },
    onBulkFileChange(kind, event) {
      const file = event?.target?.files?.[0];
      const name = file?.name || '';
      if (kind === 'wallpaper') this.bulkWallpaperName = name;
      if (kind === 'lockScreen') this.bulkLockScreenName = name;
    },
    async dispatchBulk() {
      if (this.bulkDispatching || !this.bulkReviewed) return;
      this.bulkDispatching = true;
      try {
        if (this.bulkJobType === 'APPLY_DEVICE_EXPERIENCE') {
          const wallpaper = this.$refs.bulkWallpaper?.files?.[0];
          const lockScreen = this.$refs.bulkLockScreen?.files?.[0];
          const title = (this.bulkPayload.announcement_title || '').trim();
          const message = (this.bulkPayload.announcement_message || '').trim();
          if (!wallpaper && !lockScreen && !message) throw new Error('Choose a wallpaper, lock screen image, or announcement.');
          if (Boolean(title) !== Boolean(message)) throw new Error('Announcement title and message are both required.');
          const fd = new FormData();
          if (wallpaper) fd.append('wallpaper', wallpaper);
          if (lockScreen) fd.append('lock_screen', lockScreen);
          fd.append('image_fit', this.bulkPayload.image_fit || 'fill');
          fd.append('announcement_title', title);
          fd.append('announcement_message', message);
          fd.append('announcement_severity', this.bulkPayload.announcement_severity || 'info');
          fd.append('announcement_require_ack', this.bulkPayload.announcement_require_ack ? '1' : '0');
          if (this.bulkBranchId) fd.append('branch_id', this.bulkBranchId);
          this.bulkReviewTargets.forEach(ep => fd.append('endpoint_ids', ep.id));
          fd.append('target_mode', 'selected');
          this.bulkResult = await wardenFetchJSON('/endpoints/experience/bulk', {
            method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() }, body: fd,
          });
          return;
        }
        this.bulkResult = await wardenFetchJSON('/endpoints/bulk-dispatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            type: this.bulkJobType,
            payload: this.bulkPayload,
            branch_id: this.bulkBranchId || null,
          }),
        });
      } catch (error) {
        this.bulkResult = { error: error.message };
      } finally {
        this.bulkDispatching = false;
      }
    },
  };
}

/* ── Endpoint detail page (endpoints/detail.html) ──
   tab/endpointId come from data-tab/data-endpoint-id on the root element —
   the CSP Alpine build can't pass constructor args through a bare
   x-data="endpointDetail" reference, so init() reads them off $el instead. */
function endpointDetail() {
  return {
    tab: 'overview',
    endpointId: '',
    platform: 'windows',
    capabilities: [],
    capabilityDetails: {},
    dispatchingJob: false,
    jobType: '',
    jobPayload: {},
    jobWindowsUser: '',
    jobReason: '',
    showJobModal: false,
    showRemoveEndpointModal: false,
    showNamingModal: false,
    endpointNickname: '',
    desiredHostname: '',
    renameRestart: false,
    savingNickname: false,
    removingEndpoint: false,
    startingSession: false,
    showRemoteModal: false,
    remoteAccessMode: 'full_control',
    remoteReason: '',
    remoteConsentTitle: 'Warden remote support',
    remoteConsentMessage: 'Your support technician can see this screen and, if requested, control this computer.',
    remoteRequested: { clipboard: false, file_transfer: false, process_manager: false, reboot: false },
    experienceSubmitting: false,
    experienceError: '',
    // Create-user modal state
    showCreateUserModal: false,
    newUsername: '',
    newPassword: '',
    newFullName: '',
    newIsAdmin: false,
    newMustChangePassword: true,
    creatingUser: false,
    // Policy tab state
    policyCatalog: {},
    policyCurrent: {},
    policyValues: {},
    jobTemplateName: '',
    policyFilter: '',
    expandedCategories: {},
    incidentPosting: false,
    endpointFirewallEditorOpen: false,
    endpointFirewallError: '',
    endpointFirewallRules: [],
    endpointFirewallApplications: [],
    recoveryKeyText: '',
    recoveryKeyId: '',
    revealingRecoveryKey: false,
    init() {
      this.tab = this.$el.dataset.tab || 'overview';
      this.endpointId = this.$el.dataset.endpointId || '';
      this.endpointNickname = this.$el.dataset.nickname || '';
      this.desiredHostname = this.$el.dataset.hostname || '';
      this.platform = this.$el.dataset.platform || 'windows';
      this.capabilities = JSON.parse(this.$el.dataset.capabilities || '[]');
      this.capabilityDetails = JSON.parse(this.$el.dataset.capabilityDetails || '{}');
      const companyName = JSON.parse(this.$el.dataset.companyName || '"Your organization"');
      this.remoteConsentTitle = `${companyName} secure support`;
      this.endpointFirewallApplications = JSON.parse(this.$el.dataset.firewallApplications || '[]');
      if (this.capabilityDetails.remote_input === false) this.remoteAccessMode = 'view_only';

      if (this.$el.dataset.policyCatalog) {
        this.policyCatalog = JSON.parse(this.$el.dataset.policyCatalog);
        this.policyCurrent = JSON.parse(this.$el.dataset.policyCurrent || '{}');
        for (const key in this.policyCatalog) {
          const meta = this.policyCatalog[key];
          const saved = this.policyCurrent[key];
          if (saved && 'value' in saved) {
            this.policyValues[key] = saved.value;
          } else if (saved && 'current_value' in saved && saved.current_value !== null) {
            this.policyValues[key] = saved.current_value;
          } else if (meta.kind === 'int') {
            this.policyValues[key] = meta.min;
          } else if (meta.kind === 'enum') {
            this.policyValues[key] = meta.options[0];
          } else if (meta.kind === 'string') {
            this.policyValues[key] = '';
          } else {
            this.policyValues[key] = false;
          }
        }
      }
    },
    toggleCategory(cat) {
      this.expandedCategories[cat] = !this.expandedCategories[cat];
    },
    matchesPolicyFilter(key) {
      if (!this.policyFilter) return true;
      const meta = this.policyCatalog[key];
      if (!meta) return false;
      const haystack = (meta.label + ' ' + meta.category).toLowerCase();
      return haystack.includes(this.policyFilter.toLowerCase());
    },
    categoryHasMatch(cat) {
      if (!this.policyFilter) return true;
      return Object.keys(this.policyCatalog).some(
        key => this.policyCatalog[key].category === cat && this.matchesPolicyFilter(key)
      );
    },
    pushPolicySetting(key) {
      this.jobType = 'PUSH_LOCAL_POLICY';
      this.jobWindowsUser = '';
      this.jobPayload = { settings: { [key]: this.policyValues[key] } };
      this.jobTemplateName = '';
      this.jobReason = '';
      this.showJobModal = true;
    },
    async incidentAction(action) {
      const reason = await window.wardenPrompt({
        title: action === 'contain' ? 'Contain endpoint' : 'Release endpoint',
        message: `Provide the incident or business reason for this ${action} action.`,
        detail: 'The reason is stored in the tenant audit trail.',
        label: 'Incident reason', placeholder: 'Incident number and reason',
        confirmLabel: 'Review action', tone: action === 'contain' ? 'danger' : 'warning',
      });
      if (!reason) return;
      if (action === 'contain' && !await window.wardenConfirm({
        title: 'Isolate this endpoint?',
        message: 'Warden-managed firewall rules will block ordinary network access.',
        detail: 'The protected Warden control channel remains available so the endpoint can receive investigation and release actions.',
        tone: 'danger', confirmLabel: 'Contain endpoint',
      })) return;
      this.incidentPosting = true;
      try {
        const data = await wardenFetchJSON(`/endpoints/${this.endpointId}/incident-response`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ action, reason }),
        });
        wardenToast(`${data.jobs.length} incident-response job(s) queued`, 'success');
      } catch (error) { wardenToast(error.message, 'error'); }
      finally { this.incidentPosting = false; }
    },
    applySavedPolicyTemplate(templateId, templateName) {
      this.jobType = 'PUSH_LOCAL_POLICY';
      this.jobWindowsUser = '';
      this.jobPayload = { template_id: templateId };
      this.jobTemplateName = templateName;
      this.jobReason = '';
      this.showJobModal = true;
    },
    blankEndpointFirewallRule() {
      return {
        id: crypto.randomUUID(), name: '', enabled: true, direction: 'out',
        action: 'allow', priority: 0, protocol: 'tcp', program: '', localPorts: '',
        remotePorts: '', remoteAddresses: '', profileDomain: true,
        profilePrivate: true, profilePublic: true, inventoryPath: '',
      };
    },
    openEndpointFirewallEditor() {
      this.endpointFirewallRules = [this.blankEndpointFirewallRule()];
      this.endpointFirewallError = '';
      this.endpointFirewallEditorOpen = true;
      document.body.style.overflow = 'hidden';
    },
    closeEndpointFirewallEditor() {
      this.endpointFirewallEditorOpen = false;
      document.body.style.overflow = '';
    },
    addEndpointFirewallRule() {
      this.endpointFirewallRules.push(this.blankEndpointFirewallRule());
    },
    removeEndpointFirewallRule(index) {
      if (this.endpointFirewallRules.length > 1) this.endpointFirewallRules.splice(index, 1);
    },
    endpointFirewallApplicationLabel(application) {
      const detail = [application.version, application.publisher].filter(Boolean).join(' · ');
      return `${application.name}${detail ? ` — ${detail}` : ''}`;
    },
    selectEndpointFirewallApplication(rule) {
      if (rule.inventoryPath) rule.program = rule.inventoryPath;
    },
    matchingEndpointFirewallPath(program) {
      const normalized = String(program || '').trim().toLowerCase();
      const match = this.endpointFirewallApplications.find(
        application => String(application.path || '').toLowerCase() === normalized
      );
      return match ? match.path : '';
    },
    splitFirewallValues(value) {
      return String(value || '').split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
    },
    serialiseEndpointFirewallRule(rule) {
      const profiles = [];
      if (rule.profileDomain) profiles.push('domain');
      if (rule.profilePrivate) profiles.push('private');
      if (rule.profilePublic) profiles.push('public');
      return {
        name: rule.name, enabled: Boolean(rule.enabled), direction: rule.direction, priority: Number(rule.priority || 0),
        action: rule.action, protocol: rule.protocol, program: rule.program,
        local_ports: this.splitFirewallValues(rule.localPorts),
        remote_ports: this.splitFirewallValues(rule.remotePorts),
        remote_addresses: this.splitFirewallValues(rule.remoteAddresses), profiles,
      };
    },
    applyCustomEndpointFirewallPolicy() {
      this.endpointFirewallError = '';
      const rules = this.endpointFirewallRules;
      if (!rules.length || rules.some(rule => !rule.name.trim())) {
        this.endpointFirewallError = 'Every rule needs a name.'; return;
      }
      if (rules.some(rule => !rule.profileDomain && !rule.profilePrivate && !rule.profilePublic)) {
        this.endpointFirewallError = 'Select at least one profile for every rule.'; return;
      }
      if (rules.some(rule => rule.direction === 'out' && rule.action === 'block' && !rule.program.trim())) {
        this.endpointFirewallError = 'Outbound block rules must target an application so Warden stays connected.'; return;
      }
      if (rules.some(rule => rule.direction === 'out' && rule.action === 'block' && /(^|[\\/])warden-agent\.exe$/i.test(rule.program))) {
        this.endpointFirewallError = 'The Warden agent cannot be selected for an outbound block rule.'; return;
      }
      this.jobType = 'PUSH_LOCAL_POLICY';
      this.jobWindowsUser = '';
      this.jobPayload = { settings: {
        firewall_all_profiles_enabled: true,
        windows_firewall_rules: JSON.stringify(rules.map(rule => this.serialiseEndpointFirewallRule(rule))),
      } };
      this.jobTemplateName = 'Custom endpoint firewall policy';
      this.jobReason = 'Custom endpoint firewall policy';
      this.closeEndpointFirewallEditor();
      this.showJobModal = true;
    },
    checkPolicyDrift() {
      // Read-only — not privileged, no escalation/confirm modal needed,
      // same category as Collect System Info / Compliance Scan.
      this.jobType = 'CHECK_POLICY_DRIFT';
      this.jobPayload = {};
      this.jobWindowsUser = '';
      this.jobReason = 'Manual drift check from admin console';
      this.dispatchJob();
    },
    checkTemplateDrift(keys) {
      // Scoped drift check — just this template's settings, not the full
      // ~1300-setting catalog. Non-privileged/read-only, same as the
      // global "Check Drift" button.
      this.jobType = 'CHECK_POLICY_DRIFT';
      this.jobPayload = { keys };
      this.jobWindowsUser = '';
      this.jobReason = 'Scoped drift check from admin console';
      this.dispatchJob();
    },
    syncUsers() {
      this.jobType = 'COLLECT_USERS';
      this.jobPayload = {};
      this.jobWindowsUser = '';
      this.jobReason = 'Manual user sync from admin console';
      this.dispatchJob();
    },
    collectSoftware() {
      this.jobType = 'COLLECT_SOFTWARE';
      this.jobPayload = {};
      this.jobWindowsUser = '';
      this.jobReason = 'Manual software inventory from admin console';
      this.dispatchJob();
    },
    collectSysinfo() {
      this.jobType = 'COLLECT_SYSINFO';
      this.jobPayload = {};
      this.jobWindowsUser = '';
      this.jobReason = 'Manual system info refresh from admin console';
      this.dispatchJob();
    },
    openJobModal(type, windowsUser) {
      const defaults = {
        RUN_CMD: { cmd_type: 'system_info' },
        REBOOT: { delay_seconds: 30 },
        SHUTDOWN: { delay_seconds: 30 },
        GET_EVENT_LOGS: { log_name: 'System' },
        WINDOWS_UPDATE: { action: 'check' },
        PUSH_LOCAL_POLICY: { template: 'restrict-standard-user-tools' },
        RESET_PASSWORD: { new_password: '' },
        GRANT_ELEVATION: { duration_minutes: 15 },
        CAPTURE_PACKETS: { duration_seconds: 30, max_size_mb: 4, protocol: 'any', remote_ip: '', port: 0 },
      };
      this.jobType = type;
      this.jobWindowsUser = windowsUser || '';
      this.jobPayload = defaults[type] ? { ...defaults[type] } : {};
      this.jobReason = '';
      this.showJobModal = true;
    },
    prepareBitLocker(type) {
      this.openJobModal(type, '');
      this.jobReason = type === 'ROTATE_BITLOCKER_RECOVERY'
        ? 'Scheduled BitLocker recovery-key rotation'
        : 'Enable full-volume encryption with recovery-key escrow';
    },
    async revealRecoveryKey(keyId) {
      if (!await window.wardenConfirm({
        title: 'Reveal BitLocker recovery key?',
        message: 'Use this key only to recover this Windows volume.',
        detail: 'Your identity, endpoint, volume, and time will be written to the immutable tenant audit trail.',
        tone: 'warning', confirmLabel: 'Reveal for 60 seconds',
      })) return;
      this.revealingRecoveryKey = true;
      try {
        const result = await wardenFetchJSON(`/endpoints/${this.endpointId}/recovery-keys/${encodeURIComponent(keyId)}/reveal`, {
          method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() },
        });
        this.recoveryKeyId = keyId;
        this.recoveryKeyText = result.recovery_password;
        window.setTimeout(() => {
          if (this.recoveryKeyId === keyId) { this.recoveryKeyText = ''; this.recoveryKeyId = ''; }
        }, 60000);
      } catch (error) { window.wardenToast(error.message || 'Could not reveal recovery key', 'error'); }
      finally { this.revealingRecoveryKey = false; }
    },
    async copyRecoveryKey() {
      if (!this.recoveryKeyText) return;
      await navigator.clipboard.writeText(this.recoveryKeyText);
      window.wardenToast('Recovery key copied. Clear your clipboard after use.', 'success');
    },
    async updateAgent() {
      if (!await window.wardenConfirm({
        title: 'Update the Warden Agent?',
        message: 'Install the latest verified Agent build on this endpoint.',
        detail: 'The service will restart and automatically roll back when the replacement does not become healthy.',
        confirmLabel: 'Install update',
      })) return;
      this.jobType = this.capabilities.includes('REINSTALL_AGENT') ? 'REINSTALL_AGENT' : 'UPDATE_AGENT';
      this.jobPayload = {};
      this.jobWindowsUser = '';
      this.jobReason = 'Manual update from admin console';
      this.dispatchJob();
    },
    openNamingModal() {
      this.renameRestart = false;
      this.showNamingModal = true;
      this.$nextTick(() => document.getElementById('endpoint-nickname')?.focus());
    },
    async saveNickname() {
      if (this.savingNickname) return;
      this.savingNickname = true;
      try {
        await wardenFetchJSON(`/endpoints/${this.endpointId}/nickname`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ nickname: this.endpointNickname }),
        });
        location.reload();
      } catch (error) { window.wardenToast(error.message, 'error'); }
      finally { this.savingNickname = false; }
    },
    async renameHostname() {
      this.jobType = 'CONFIGURE_DEVICE_IDENTITY';
      this.jobPayload = { hostname: this.desiredHostname.trim(), restart: this.renameRestart };
      this.jobWindowsUser = '';
      this.jobReason = 'Administrator requested hostname change';
      const result = await this.dispatchJob();
      if (result) this.showNamingModal = false;
    },
    async dispatchJob() {
      if (this.dispatchingJob) return;
      this.dispatchingJob = true;
      try {
        const res = await wardenFetchJSON(`/endpoints/${this.endpointId}/dispatch-job`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            type: this.jobType,
            payload: this.jobPayload,
            windows_user: this.jobWindowsUser,
            reason: this.jobReason,
          }),
        });
        this.showJobModal = false;
        const awaitingApproval = res.status === 'pending_approval' || res.status === 'pending' || res.status === 'pending_secondary';
        window.wardenToast(res.message || (awaitingApproval ? 'Request submitted and awaiting administrator approval' : 'Job dispatched successfully'), awaitingApproval ? 'info' : 'success');
        const liveJobs = document.getElementById('endpoint-job-live');
        if (liveJobs && window.htmx) window.htmx.trigger(liveJobs, 'refresh');
        return res;
      } catch (error) {
        window.wardenToast(error.message || 'Failed to dispatch job', 'error');
      } finally {
        this.dispatchingJob = false;
      }
    },
    async removeEndpointFromWarden() {
      if (this.removingEndpoint) return;
      this.removingEndpoint = true;
      try {
        await wardenFetchJSON(`/endpoints/${this.endpointId}/remove-from-warden`, {
          method: 'POST',
          headers: { 'X-CSRFToken': getCsrfToken() },
        });
        window.location.assign('/endpoints?removed=1');
      } catch (error) {
        window.wardenToast(error.message || 'Failed to remove endpoint', 'error');
        this.removingEndpoint = false;
      }
    },
    async startRemoteSession() {
      if (this.startingSession || !this.remoteReason.trim() || !this.remoteModeAvailable()) return;
      // Open the tab synchronously from the click event so browsers do not
      // classify it as an async popup after the session API request finishes.
      const remoteTab = window.open('about:blank', '_blank');
      if (!remoteTab) {
        window.wardenToast('Allow pop-ups for Warden to open Remote Control in a new tab', 'error');
        return;
      }
      remoteTab.document.title = 'Starting Warden Remote Control…';
      remoteTab.document.body.textContent = 'Starting secure remote session…';
      this.startingSession = true;
      try {
        const res = await wardenFetchJSON(`/endpoints/${this.endpointId}/start-session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            access_mode: this.remoteAccessMode,
            reason: this.remoteReason.trim(),
            consent_title: this.remoteConsentTitle.trim(),
            consent_message: this.remoteConsentMessage.trim(),
            requested_capabilities: this.remoteRequested,
          }),
        });
        if (res.ok && res.viewer_url) {
          this.showRemoteModal = false;
          remoteTab.location.replace(res.viewer_url);
        } else {
          const message = res.message || res.error || 'Failed to start remote session';
          remoteTab.document.title = 'Warden Remote Control unavailable';
          remoteTab.document.body.textContent = `Could not start remote control: ${message}. Return to Warden to retry.`;
          window.wardenToast(message, 'error');
        }
      } catch (error) {
        const message = error.message || 'Failed to start remote session';
        remoteTab.document.title = 'Warden Remote Control unavailable';
        remoteTab.document.body.textContent = `Could not start remote control: ${message}. Return to Warden to retry.`;
        window.wardenToast(message, 'error');
      } finally {
        this.startingSession = false;
      }
    },
    remoteModeAvailable() {
      if (this.remoteAccessMode === 'view_only') return this.capabilityDetails.remote_consent !== false;
      if (this.remoteAccessMode === 'full_control') {
        return this.capabilityDetails.remote_input !== false && this.capabilityDetails.remote_consent !== false;
      }
      return this.capabilityDetails.remote_input !== false;
    },
    remoteCapabilityEnabled(name) {
      if (this.remoteAccessMode === 'view_only') return false;
      if (name === 'clipboard') return this.capabilityDetails.remote_clipboard !== false;
      if (name === 'process_manager') return this.capabilityDetails.remote_process_manager !== false;
      return true;
    },
    async submitExperience(formEl) {
      if (this.experienceSubmitting) return;
      this.experienceSubmitting = true;
      this.experienceError = '';
      try {
        const data = await wardenFetchJSON(`/endpoints/${this.endpointId}/experience`, {
          method: 'POST', body: new FormData(formEl),
          headers: { 'X-CSRFToken': getCsrfToken(), 'Accept': 'application/json' },
        });
        window.wardenToast(data.message, 'success');
        window.location.assign(`/endpoints/${this.endpointId}?tab=jobs`);
      } catch (error) {
        this.experienceError = error.message || 'Could not apply device experience';
      } finally {
        this.experienceSubmitting = false;
      }
    },
    deployApp(appUrl, sha256, reason, ext, installArgs) {
      this.jobType = 'INSTALL_APP';
      this.jobWindowsUser = '';
      // ext is needed because appUrl is the download route
      // (/api/agent/apps/<id>/download) and never itself carries a file
      // extension — the agent can't derive installer.exe vs installer.msi
      // from the URL alone. See agent-go/commands.go's installApp().
      this.jobPayload = { app_url: appUrl, sha256: sha256, ext: ext || '.exe', install_args: installArgs || '' };
      this.jobReason = reason;
      this.showJobModal = true;
    },
    uninstallApp(productName, reason) {
      this.jobType = 'UNINSTALL_APP';
      this.jobWindowsUser = '';
      this.jobPayload = { product_name: productName };
      this.jobReason = reason;
      this.showJobModal = true;
    },
    openCreateUserModal() {
      this.newUsername = '';
      this.newPassword = '';
      this.newFullName = '';
      this.newIsAdmin = false;
      this.newMustChangePassword = true;
      this.showCreateUserModal = true;
    },
    async createUser() {
      if (this.creatingUser || !this.newUsername || !this.newPassword) return;
      this.creatingUser = true;
      try {
        await wardenFetchJSON(`/endpoints/${this.endpointId}/dispatch-job`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            type: 'CREATE_USER',
            payload: {
              username: this.newUsername,
              password: this.newPassword,
              full_name: this.newFullName,
              is_admin: this.newIsAdmin,
              must_change_password: this.newMustChangePassword,
            },
            reason: 'Created from admin console',
          }),
        });
        this.showCreateUserModal = false;
        window.wardenToast('Job dispatched successfully', 'success');
      } catch (error) {
        window.wardenToast(error.message || 'Failed to create user', 'error');
      } finally {
        this.creatingUser = false;
      }
    },
  };
}

/* ── Compliance page (compliance/index.html) ──
   policyChecks' initial (all-checked) value comes from data-all-checks. */
function compliancePage() {
  return {
    showPolicies: false,
    showNewPolicy: false,
    policyName: '',
    policyDesc: '',
    policyBranch: '',
    policyChecks: [],
    saving: false,
    scanning: false,
    init() {
      try { this.policyChecks = JSON.parse(this.$el.dataset.allChecks || '[]'); }
      catch (_) { this.policyChecks = []; }
    },
    toggleCheck(check) {
      const idx = this.policyChecks.indexOf(check);
      if (idx === -1) this.policyChecks.push(check);
      else this.policyChecks.splice(idx, 1);
    },
    async scanAll() {
      if (this.scanning) return;
      this.scanning = true;
      try {
        const res = await wardenFetchJSON('/compliance/scan-all', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({}),
        });
        window.wardenToast(res.message || 'Scan dispatched to all endpoints', 'success');
      } catch (error) {
        window.wardenToast(error.message || 'Failed to start scan', 'error');
      } finally {
        this.scanning = false;
      }
    },
    async savePolicy() {
      if (this.saving) return;
      this.saving = true;
      try {
        const res = await wardenFetchJSON('/compliance/policies', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            name: this.policyName,
            description: this.policyDesc,
            branch_id: this.policyBranch || null,
            checks: this.policyChecks,
          }),
        });
        window.wardenToast('Policy created', 'success');
        this.showNewPolicy = false;
        this.policyName = '';
        this.policyDesc = '';
        this.policyBranch = '';
        try { this.policyChecks = JSON.parse(this.$el.dataset.allChecks || '[]'); } catch (_) {}
        setTimeout(() => location.reload(), 600);
      } catch (error) {
        window.wardenToast(error.message || 'Failed to create policy', 'error');
      } finally {
        this.saving = false;
      }
    },
  };
}

/* ── Scheduled jobs page (schedule/index.html) ──
   jobType's initial value comes from data-default-job-type. */
function scheduledJobsPage() {
  return {
    showNewJob: false,
    jobName: '',
    jobType: '',
    jobInterval: '86400',
    jobTarget: 'all',
    jobBranch: '',
    jobEndpoint: '',
    saving: false,
    runningJobs: {},
    init() {
      this.jobType = this.$el.dataset.defaultJobType || '';
    },
    async saveJob() {
      if (this.saving) return;
      this.saving = true;
      const payload = {
        name: this.jobName,
        job_type: this.jobType,
        interval_seconds: parseInt(this.jobInterval),
        branch_id: this.jobTarget === 'branch' ? (this.jobBranch || null) : null,
        endpoint_id: this.jobTarget === 'endpoint' ? (this.jobEndpoint || null) : null,
      };
      try {
        await wardenFetchJSON('/schedule/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify(payload),
        });
        window.wardenToast('Schedule created', 'success');
        this.showNewJob = false;
        this.jobName = '';
        setTimeout(() => location.reload(), 600);
      } catch (error) {
        window.wardenToast(error.message || 'Failed to create schedule', 'error');
      } finally {
        this.saving = false;
      }
    },
    async runNow(id) {
      if (this.runningJobs[id]) return;
      this.runningJobs[id] = true;
      try {
        const res = await wardenFetchJSON('/schedule/' + id + '/run-now', { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } });
        if (res.dispatched !== undefined) {
          window.wardenToast('Dispatched to ' + res.dispatched + ' endpoint(s)', 'success');
        } else {
          window.wardenToast(res.message || 'Run dispatched', 'success');
        }
      } catch (error) {
        window.wardenToast(error.message || 'Could not run schedule', 'error');
      } finally {
        delete this.runningJobs[id];
      }
    },
  };
}

/* ── Security settings page (settings/security.html) ──
   Replaces inline onclick="" attributes + an unnonced <script> block, both
   of which CSP blocks outright regardless of the rest of the app's nonce. */
function securitySettingsPage() {
  return {
    posting: false,
    tlsResult: '',
    async post(formEl, url) {
      if (this.posting) return;
      this.posting = true;
      const fd = formEl ? new FormData(formEl) : new FormData();
      if (!formEl) fd.append('csrf_token', getCsrfToken());
      try {
        await wardenFetchJSON(url, { method: 'POST', body: fd });
        location.reload();
      } catch (error) {
        window.wardenToast(error.message || 'Request failed', 'error');
      } finally {
        this.posting = false;
      }
    },
    async confirmAndPost(message, url) {
      if (!await window.wardenConfirm({ title: 'Change security protection?', message, tone: 'danger', confirmLabel: 'Apply change' })) return;
      this.post(null, url);
    },
    async rotatePins(formEl) {
      if (this.posting) return;
      const fd = new FormData(formEl);
      const endpointId = String(fd.get('endpoint_id') || '');
      const fingerprints = String(fd.get('fingerprints') || '').split(/[\s,]+/).map(value => value.trim()).filter(Boolean);
      if (!endpointId || fingerprints.length < 1 || fingerprints.length > 3) {
        wardenToast('Choose an endpoint and enter 1 to 3 SHA-256 fingerprints', 'error');
        return;
      }
      if (!await window.wardenConfirm({
        title: 'Rotate endpoint trust pins?',
        message: 'Queue this TLS trust-pin rotation for approval.',
        detail: 'A wrong fingerprint can disconnect the endpoint. Two different administrators must approve this operation.',
        tone: 'danger', confirmLabel: 'Queue rotation',
      })) return;
      this.posting = true;
      this.tlsResult = '';
      try {
        const data = await wardenFetchJSON(`/endpoints/${endpointId}/dispatch-job`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ type: 'ROTATE_TLS_PINS', payload: { fingerprints }, reason: String(fd.get('reason') || 'TLS certificate rotation') }),
        });
        this.tlsResult = data.status === 'pending_secondary' ? 'First approval recorded; a second administrator must approve.' : 'Rotation request queued for approval.';
      } catch (error) { wardenToast(error.message, 'error'); }
      finally { this.posting = false; }
    },
  };
}

function adminProfileForm() {
  return {
    name: '', email: '', currentPassword: '', photo: null, preview: '', error: '', saving: false,
    init() {
      this.name = this.$el.dataset.name || '';
      this.email = this.$el.dataset.email || '';
      this.preview = this.$el.dataset.photo || '';
    },
    async selectPhoto(event) {
      try { this.photo = await normalizeProfilePhoto(event.target.files[0]); this.preview = this.photo; }
      catch (error) { this.error = error.message; event.target.value = ''; }
    },
    removePhoto() { this.photo = ''; this.preview = ''; },
    async save() {
      if (this.saving) return;
      this.saving = true;
      this.error = '';
      try {
        const result = await wardenFetchJSON('/users/profile', {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ full_name: this.name, email: this.email, current_password: this.currentPassword,
            ...(this.photo !== null ? { profile_photo: this.photo } : {}) }),
        });
        if (result.sign_in_required) window.location.assign('/login');
        else window.location.reload();
      } catch (error) { this.error = error.message; }
      finally { this.saving = false; this.currentPassword = ''; }
    },
  };
}

/* ── Change password form (settings/index.html) ── */
function passwordChangeForm() {
  return {
    done: false,
    error: '',
    submitting: false,
    async submit(formEl) {
      if (this.submitting) return;
      this.submitting = true;
      this.error = '';
      this.done = false;
      const fd = new FormData(formEl);
      try {
        const r = await fetch('/change-password', { method: 'POST', body: fd });
        if (r.redirected) { window.location.href = r.url; return; }
        const text = await r.text();
        let res = {};
        try { res = text ? JSON.parse(text) : {}; } catch (_) {}
        if (!r.ok || res.error) throw new Error(res.error || 'Password change failed');
        this.done = true;
        formEl.reset();
      } catch (error) {
        this.error = error.message || 'Password change failed';
      } finally {
        this.submitting = false;
      }
    },
  };
}

/* ── Notification preferences form (settings/index.html) ── */
function notificationPrefsForm() {
  return {
    saved: false,
    saving: false,
    error: '',
    async submit(formEl) {
      if (this.saving) return;
      this.saving = true;
      this.error = '';
      const fd = new FormData(formEl);
      try {
        const r = await fetch('/settings/notifications', { method: 'POST', body: fd });
        if (!r.ok) throw new Error('Could not save notification preferences');
        this.saved = true;
        setTimeout(() => { this.saved = false; }, 2000);
      } catch (error) {
        this.error = error.message;
        window.wardenToast(this.error, 'error');
      } finally {
        this.saving = false;
      }
    },
  };
}

/* ── Alert thresholds form (settings/thresholds.html) ── */
function thresholdsForm() {
  return {
    saved: false,
    error: '',
    saveUrl: '',
    saving: false,
    init() {
      this.saveUrl = this.$el.dataset.saveUrl || '';
    },
    async submit() {
      if (this.saving) return;
      this.saving = true;
      this.saved = false;
      this.error = '';
      const body = {
        cpu_pct: this.$refs.cpu.value,
        ram_pct: this.$refs.ram.value,
        disk_free_gb: this.$refs.disk.value,
        offline_minutes: this.$refs.offline.value,
      };
      try {
        await wardenFetchJSON(this.saveUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify(body),
        });
        this.saved = true;
        setTimeout(() => { this.saved = false; }, 2000);
      } catch (error) {
        this.error = error.message;
      } finally {
        this.saving = false;
      }
    },
  };
}

/* ── App upload modal (apps/library.html) ── */
function uploadModal() {
  return {
    showUpload: false,
    uploading: false,
    result: null,
    showEdit: false,
    editId: '',
    editName: '',
    editVersion: '',
    editDescription: '',
    editInstallArgs: '',
    editSelfService: false,
    editError: '',
    editing: false,
    showDeploy: false,
    deployId: '',
    deployName: '',
    deployExt: '',
    deployEndpointIds: [],
    deployResult: '',
    deploying: false,
    async submit(formEl) {
      if (this.uploading) return;
      this.uploading = true;
      const fd = new FormData(formEl);
      try {
        this.result = await wardenFetchJSON('/apps/upload', { method: 'POST', body: fd, headers: { 'X-CSRFToken': getCsrfToken() } });
      } catch (error) {
        this.result = { error: error.message };
      } finally {
        this.uploading = false;
      }
    },
    close() {
      this.showUpload = false;
      this.result = null;
    },
    openEdit(data) {
      this.editId = data.id;
      this.editName = data.name;
      this.editVersion = data.version;
      this.editDescription = data.description || '';
      this.editInstallArgs = data.installArgs || '';
      this.editSelfService = data.selfService === 'true';
      this.editError = '';
      this.showEdit = true;
    },
    async saveEdit() {
      this.editing = true;
      this.editError = '';
      try {
        await wardenFetchJSON(`/apps/${this.editId}/update`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ name: this.editName, version: this.editVersion, description: this.editDescription, install_args: this.editInstallArgs, self_service: this.editSelfService }),
        });
        window.location.reload();
      } catch (error) {
        this.editError = error.message;
      } finally {
        this.editing = false;
      }
    },
    async removeApp(id, name) {
      if (!await window.wardenConfirm({
        title: 'Delete application package?', message: `Remove ${name} from the Warden application library?`,
        detail: 'Existing installed copies remain on endpoints. Future deployments using this package will no longer be available.',
        tone: 'danger', confirmLabel: 'Delete package',
      })) return;
      try {
        await wardenFetchJSON(`/apps/${id}/delete`, { method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() } });
        window.location.reload();
      } catch (error) {
        wardenToast(error.message, 'error');
      }
    },
    openDeploy(id, name, ext) {
      this.deployId = id;
      this.deployName = name;
      this.deployExt = String(ext || '').toLowerCase();
      this.deployEndpointIds = [];
      this.deployResult = '';
      this.showDeploy = true;
    },
    compatibleEndpoint(platform) {
      const formats = { windows: ['exe', 'msi'], linux: ['deb', 'rpm'], darwin: ['pkg'] };
      return (formats[String(platform || 'windows').toLowerCase()] || []).includes(this.deployExt);
    },
    async deploySelected() {
      this.deploying = true;
      try {
        const data = await wardenFetchJSON(`/apps/${this.deployId}/deploy`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ endpoint_ids: this.deployEndpointIds }),
        });
        this.deployResult = `${data.dispatched} deployment job(s) queued${data.skipped ? `; ${data.skipped} skipped` : ''}.`;
        this.deployEndpointIds = [];
      } catch (error) { wardenToast(error.message, 'error'); }
      finally { this.deploying = false; }
    },
  };
}

function enrollmentTokenForm() {
  return { reusable: true };
}

function enrollmentProfileForm() {
  return { wardenOnly: true };
}

/* ── Root app ──────────────────────────────── */
function wardenApp() {
  return {
    mobileMenuOpen: false,
    sidebarStateClass: '',
    navigationExpanded: false,
    navigationHidden: true,
    navigationInert: true,
    commandOpen: false,
    commandQuery: '',
    flashes: [],
    _flashId: 0,

    init() {
      this.syncNavigationState();
    },

    syncNavigationState() {
      this.sidebarStateClass = this.mobileMenuOpen ? 'sidebar-mobile-open' : '';
      this.navigationExpanded = this.mobileMenuOpen;
      this.navigationHidden = !this.navigationExpanded;
      this.navigationInert = !this.navigationExpanded;
    },

    // Flash auto-dismiss is handled per-element in base.html
    // (x-init="setTimeout(() => $el.remove(), 5000)") — nothing to wire up here.


    addFlash(type, message) {
      const id = ++this._flashId;
      this.flashes.push({ id, type, message });
      setTimeout(() => {
        this.flashes = this.flashes.filter(f => f.id !== id);
      }, 5000);
    },

    dismissFlash(id, el) {
      if (el) { el.style.opacity = '0'; setTimeout(() => el.remove(), 200); return; }
      this.flashes = this.flashes.filter(f => f.id !== id);
    },

    openCommand() {
      this.closeMobileNavigation(false);
      this.commandOpen = true;
      this.commandQuery = '';
      this.$nextTick(() => document.getElementById('warden-command-input')?.focus());
    },

    closeCommand() {
      this.commandOpen = false;
      this.commandQuery = '';
    },

    closeOverlays() {
      if (this.commandOpen) this.closeCommand();
      else this.closeMobileNavigation();
    },

    commandMatches(text) {
      return !this.commandQuery.trim() || text.toLowerCase().includes(this.commandQuery.trim().toLowerCase());
    },

    openFirstCommandResult() {
      const firstVisible = Array.from(document.querySelectorAll('.command-results a'))
        .find((link) => link.offsetParent !== null);
      if (firstVisible) window.location.assign(firstVisible.href);
    },

    toggleNavigation() {
      if (this.mobileMenuOpen) { this.closeMobileNavigation(); return; }
      this._navigationOpener = document.activeElement;
      this.mobileMenuOpen = true;
      this.syncNavigationState();
      this.$nextTick(() => document.querySelector('#app-sidebar .sidebar-close')?.focus());
    },

    closeMobileNavigation(restoreFocus = true) {
      if (!this.mobileMenuOpen) return;
      this.mobileMenuOpen = false;
      this.syncNavigationState();
      if (restoreFocus) this.$nextTick(() => this._navigationOpener?.focus());
    },

    handleNavigationClick(event) {
      if (event.target.closest('a[href]')) this.closeMobileNavigation(false);
    },
  };
}

/* ── Login form ────────────────────────────── */
function loginForm() {
  return {
    email: '',
    password: '',
    showPassword: false,
    needsMfa: false,
    mfaToken: '',
    totpCode: '',
    loading: false,
    error: '',
    totpDigits: ['', '', '', '', '', ''],

    async submit() {
      this.loading = true;
      this.error = '';
      try {
        const data = await wardenFetchJSON('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify({ email: this.email, password: this.password }),
        });
        if (data.needs_mfa) {
          this.needsMfa = true;
          this.mfaToken = data.mfa_token;
          this.$nextTick(() => document.getElementById('totp-0')?.focus());
        } else if (data.error) {
          this.error = data.error;
        } else if (data.redirect) {
          window.location.href = data.redirect;
        }
      } catch (e) {
        this.error = e.message || 'Network error. Please try again.';
      } finally {
        this.loading = false;
      }
    },

    async submitMfa() {
      this.loading = true;
      this.error = '';
      const code = this.totpDigits.join('');
      try {
        const data = await wardenFetchJSON('/login/mfa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
          body: JSON.stringify({ mfa_token: this.mfaToken, code }),
        });
        if (data.error) {
          this.error = data.error;
          this.totpDigits = ['', '', '', '', '', ''];
          this.$nextTick(() => document.getElementById('totp-0')?.focus());
        } else if (data.redirect) {
          window.location.href = data.redirect;
        }
      } catch (e) {
        this.error = e.message || 'Network error. Please try again.';
      } finally {
        this.loading = false;
      }
    },

    onTotpInput(idx, e) {
      const val = e.target.value.replace(/\D/g, '').slice(-1);
      this.totpDigits[idx] = val;
      if (val && idx < 5) {
        this.$nextTick(() => document.getElementById(`totp-${idx + 1}`)?.focus());
      }
      if (this.totpDigits.every(d => d !== '')) {
        this.submitMfa();
      }
    },

    onTotpKeydown(idx, e) {
      if (e.key === 'Backspace' && !this.totpDigits[idx] && idx > 0) {
        this.$nextTick(() => document.getElementById(`totp-${idx - 1}`)?.focus());
      }
    },
  };
}

/* ── Tab panel ─────────────────────────────── */
function tabPanel(defaultTab) {
  return {
    activeTab: defaultTab,
    setTab(tab) { this.activeTab = tab; },
    isTab(tab) { return this.activeTab === tab; },
  };
}

/* ── Slide panel ───────────────────────────── */
function slidePanel() {
  return {
    open: false,
    title: '',

    show(title) {
      this.title = title || '';
      this.open = true;
      document.body.style.overflow = 'hidden';
    },

    close() {
      this.open = false;
      document.body.style.overflow = '';
    },
  };
}

/* ── Policy template builder (settings/policy_templates.html) ──
   catalog comes from data-catalog: {key: {category,label,kind,min,max,values}} */
function policyTemplateBuilder() {
  return {
    open: false,
    builderTitle: 'Create Policy Template',
    deploymentOpen: false,
    deploymentTemplateId: '',
    deploymentTemplateName: '',
    deploymentSettingCount: 0,
    deploymentBranchId: '',
    deploymentPlatform: 'windows',
    deploymentTag: '',
    deploymentRolloutPercentage: 10,
    deploymentReason: '',
    deploymentIdempotencyKey: '',
    deploymentError: '',
    deploymentResult: '',
    deploying: false,
    cancellingDeployments: {},
    retryingDeployments: {},
    catalog: {},
    included: {},
    values: {},

    filterText: '',
    expandedCategories: {},
    init() {
      this.catalog = JSON.parse(this.$el.dataset.catalog || '{}');
      for (const key in this.catalog) {
        const meta = this.catalog[key];
        this.included[key] = false;
        if (meta.kind === 'int') this.values[key] = meta.min;
        else if (meta.kind === 'enum') this.values[key] = meta.options[0];
        else if (meta.kind === 'string') this.values[key] = '';
        else this.values[key] = 'false';
      }
    },
    toggleCategory(cat) {
      this.expandedCategories[cat] = !this.expandedCategories[cat];
    },
    matchesFilter(key) {
      if (!this.filterText) return true;
      const meta = this.catalog[key];
      if (!meta) return false;
      return (meta.label + ' ' + meta.category).toLowerCase().includes(this.filterText.toLowerCase());
    },
    categoryHasMatch(cat) {
      if (!this.filterText) return true;
      return Object.keys(this.catalog).some(
        key => this.catalog[key].category === cat && this.matchesFilter(key)
      );
    },
    selectAllInCategory(cat) {
      for (const key in this.catalog) {
        if (this.catalog[key].category === cat && !this.catalog[key].readonly) {
          this.included[key] = true;
        }
      }
    },
    clearAllInCategory(cat) {
      for (const key in this.catalog) {
        if (this.catalog[key].category === cat) this.included[key] = false;
      }
    },
    // Starter presets — built only from the hand-picked catalog (stable,
    // known key names) rather than the ~1000 ADMX-derived ones, whose
    // exact key names are auto-generated from Microsoft's own policy
    // names and not meant to be hardcoded here. Still just pre-fills the
    // form; the admin reviews and submits like any other template.
    applyPreset(name) {
      const presets = {
        privacy: {
          telemetry_level: 'Basic',
          cortana_enabled: false,
          onedrive_sync_enabled: false,
          windows_spotlight_enabled: false,
          llmnr_enabled: false,
        },
        remote_access: {
          rdp_network_level_auth_required: true,
          guest_account_enabled: false,
          remote_assistance_enabled: false,
          remote_registry_service_enabled: false,
          require_ctrl_alt_del: true,
          hide_last_signed_in_user: true,
          screen_lock_timeout_minutes: 10,
        },
      };
      const preset = presets[name];
      if (!preset) return;
      for (const key in preset) {
        if (!(key in this.catalog)) continue;
        this.included[key] = true;
        this.values[key] = this.catalog[key].kind === 'bool' ? String(preset[key]) : preset[key];
      }
    },
    resetBuilder() {
      this.filterText = '';
      this.expandedCategories = {};
      for (const key in this.catalog) {
        const meta = this.catalog[key];
        this.included[key] = false;
        if (meta.kind === 'int') this.values[key] = meta.min;
        else if (meta.kind === 'enum') this.values[key] = meta.options[0];
        else if (meta.kind === 'string') this.values[key] = '';
        else this.values[key] = 'false';
      }
    },
    show() {
      this.resetBuilder();
      this.builderTitle = 'Create Policy Template';
      this.open = true;
      document.body.style.overflow = 'hidden';
      this.$nextTick(() => {
        this.$refs.templateName.value = '';
        this.$refs.templateDescription.value = '';
        this.$refs.templateName.focus();
      });
    },
    cloneFromElement(element) {
      let settings = {};
      try { settings = JSON.parse(element.dataset.templateSettings || '{}'); }
      catch (_) { window.wardenToast('This template could not be loaded.', 'error'); return; }
      this.resetBuilder();
      for (const key in settings) {
        if (!(key in this.catalog) || this.catalog[key].readonly) continue;
        this.included[key] = true;
        this.values[key] = this.catalog[key].kind === 'bool' ? String(settings[key]) : settings[key];
        this.expandedCategories[this.catalog[key].category] = true;
      }
      this.builderTitle = 'Clone and modify policy';
      this.open = true;
      document.body.style.overflow = 'hidden';
      this.$nextTick(() => {
        this.$refs.templateName.value = `Copy of ${element.dataset.templateName || 'Policy'}`;
        this.$refs.templateDescription.value = element.dataset.templateDescription || '';
        this.$refs.templateName.focus();
        this.$refs.templateName.select();
      });
    },
    close() {
      this.open = false;
      document.body.style.overflow = '';
    },
    showDeployment(templateId, templateName, settingCount) {
      this.deploymentTemplateId = templateId;
      this.deploymentTemplateName = templateName;
      this.deploymentSettingCount = Number(settingCount) || 0;
      this.deploymentBranchId = '';
      this.deploymentPlatform = 'windows';
      this.deploymentTag = '';
      this.deploymentRolloutPercentage = 10;
      this.deploymentReason = '';
      this.deploymentIdempotencyKey = crypto.randomUUID();
      this.deploymentError = '';
      this.deploymentResult = '';
      this.deploymentOpen = true;
      document.body.style.overflow = 'hidden';
    },
    closeDeployment() {
      if (this.deploying) return;
      this.deploymentOpen = false;
      document.body.style.overflow = '';
    },
    async deployToBranch() {
      if (this.deploying || !this.deploymentBranchId || this.deploymentResult) return;
      this.deploying = true;
      this.deploymentError = '';
      try {
        const result = await wardenFetchJSON(
          `/settings/policy-templates/${encodeURIComponent(this.deploymentTemplateId)}/deploy`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
            body: JSON.stringify({
              branch_id: this.deploymentBranchId,
              platform: this.deploymentPlatform,
              tag: this.deploymentTag,
              rollout_percentage: Number(this.deploymentRolloutPercentage),
              reason: this.deploymentReason,
              idempotency_key: this.deploymentIdempotencyKey,
            }),
          },
        );
        const failed = result.failed ? ` ${result.failed} could not be queued.` : '';
        this.deploymentResult = `${result.queued} endpoint${result.queued === 1 ? '' : 's'} queued from ${result.eligible} eligible in ${result.branch} (${result.rollout_percentage}% ring).${failed}`;
        window.wardenToast(`Policy queued for ${result.queued} endpoint${result.queued === 1 ? '' : 's'}.`, 'success');
      } catch (error) {
        this.deploymentError = error.message || 'Could not deploy this policy.';
      } finally {
        this.deploying = false;
      }
    },
    async cancelDeployment(deploymentId) {
      if (this.cancellingDeployments[deploymentId]) return;
      if (!await window.wardenConfirm({
        title: 'Cancel policy rollout?',
        message: 'Cancel every job in this rollout that has not started yet.',
        detail: 'Running or completed jobs are not reversed. Devices that already applied the policy keep their current configuration.',
        tone: 'danger', confirmLabel: 'Cancel queued jobs',
      })) return;
      this.cancellingDeployments[deploymentId] = true;
      try {
        const result = await wardenFetchJSON(`/settings/policy-deployments/${encodeURIComponent(deploymentId)}/cancel`, {
          method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() },
        });
        window.wardenToast(`Cancelled ${result.cancelled} queued job${result.cancelled === 1 ? '' : 's'}.`, 'success');
        window.location.reload();
      } catch (error) {
        window.wardenToast(error.message || 'Could not cancel deployment', 'error');
        delete this.cancellingDeployments[deploymentId];
      }
    },
    async retryDeployment(deploymentId) {
      if (this.retryingDeployments[deploymentId]) return;
      this.retryingDeployments[deploymentId] = true;
      try {
        const result = await wardenFetchJSON(`/settings/policy-deployments/${encodeURIComponent(deploymentId)}/retry`, {
          method: 'POST', headers: { 'X-CSRFToken': getCsrfToken() },
        });
        window.wardenToast(`Requeued ${result.retried} endpoint${result.retried === 1 ? '' : 's'}.`, 'success');
        window.location.reload();
      } catch (error) {
        window.wardenToast(error.message || 'Could not retry deployment', 'error');
        delete this.retryingDeployments[deploymentId];
      }
    },
    toggle(key) {
      this.included[key] = !this.included[key];
    },
    // Bound to the form's plain @submit (no .prevent) so this runs
    // synchronously right before the browser's own native POST goes out —
    // populates the hidden field with only the settings actually checked.
    assembleSettingsJson() {
      const settings = {};
      for (const key in this.included) {
        if (!this.included[key]) continue;
        settings[key] = this.catalog[key].kind === 'bool'
          ? this.values[key] === 'true'
          : this.values[key];
      }
      document.getElementById('policy-template-settings-json').value = JSON.stringify(settings);
    },
  };
}

/* ── Password reset modal ──────────────────── */
function passwordReset() {
  return {
    open: false,
    endpoint: null,
    windowsUser: null,
    autoGenerate: true,
    password: '',
    mustChange: true,
    loading: false,
    result: null,
    error: '',

    show(endpointId, endpointName, winUser) {
      this.endpoint = { id: endpointId, name: endpointName };
      this.windowsUser = winUser;
      this.autoGenerate = true;
      this.password = '';
      this.mustChange = true;
      this.result = null;
      this.error = '';
      this.open = true;
    },

    generatePassword() {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
      this.password = Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    },

    async submit() {
      if (!this.autoGenerate && !this.password) { this.error = 'Enter a password'; return; }
      if (this.autoGenerate) this.generatePassword();
      this.loading = true;
      this.error = '';
      try {
        const data = await wardenFetchJSON(`/endpoints/${this.endpoint.id}/users/${this.windowsUser}/reset-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ password: this.password, must_change: this.mustChange }),
        });
        if (data.error) { this.error = data.error; }
        else { this.result = this.password; }
      } catch (e) {
        this.error = 'Failed to dispatch job.';
      } finally {
        this.loading = false;
      }
    },

    copyPassword() {
      navigator.clipboard.writeText(this.result).catch(() => {});
    },

    close() { this.open = false; },
  };
}

/* ── Escalation approval panel ─────────────── */
function escalationApproval() {
  return {
    savePolicy: false,
    policyScope: 'this_user_this_endpoint',
    policyDuration: '30_days',
    policyNote: '',
    loading: false,

    async approve(requestId, once = false) {
      this.loading = true;
      try {
        const body = once
          ? { action: 'approve_once' }
          : {
              action: 'approve_save',
              scope: this.policyScope,
              duration: this.policyDuration,
              note: this.policyNote,
            };
        const res = await fetch(`/escalations/${requestId}/review`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify(body),
        });
        if (res.ok) { htmx.trigger('#escalations-list', 'refresh'); }
      } finally {
        this.loading = false;
      }
    },

    async deny(requestId) {
      this.loading = true;
      try {
        await fetch(`/escalations/${requestId}/review`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ action: 'deny' }),
        });
        htmx.trigger('#escalations-list', 'refresh');
      } finally {
        this.loading = false;
      }
    },
  };
}

/* ── Countdown timer ───────────────────────── */
function countdownTimer(expiresAt) {
  return {
    remaining: '',
    urgency: 'ok',
    _interval: null,

    init() {
      this.tick();
      this._interval = setInterval(() => this.tick(), 1000);
    },

    tick() {
      const diff = Math.max(0, new Date(expiresAt) - Date.now());
      const secs = Math.floor(diff / 1000);
      if (secs <= 0) {
        this.remaining = 'Expired';
        this.urgency = 'urgent';
        clearInterval(this._interval);
        return;
      }
      const m = Math.floor(secs / 60);
      const s = secs % 60;
      this.remaining = `${m}:${String(s).padStart(2, '0')}`;
      this.urgency = secs < 60 ? 'urgent' : secs < 180 ? 'warn' : 'ok';
    },

    destroy() { clearInterval(this._interval); },
  };
}

/* ── App deploy modal ──────────────────────── */
function deployApp(appId, appName) {
  return {
    open: false,
    appId,
    appName,
    endpoints: [],
    selected: [],
    loading: false,
    deploying: false,

    async show() {
      this.open = true;
      this.loading = true;
      try {
        const data = await wardenFetchJSON('/api/endpoints?status=online');
        this.endpoints = data.endpoints || [];
      } finally {
        this.loading = false;
      }
    },

    toggle(id) {
      const idx = this.selected.indexOf(id);
      if (idx === -1) this.selected.push(id);
      else this.selected.splice(idx, 1);
    },

    async deploy() {
      if (!this.selected.length) return;
      this.deploying = true;
      try {
        await fetch(`/apps/${this.appId}/deploy`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ endpoint_ids: this.selected }),
        });
        this.open = false;
        window.location.reload();
      } finally {
        this.deploying = false;
      }
    },

    close() { this.open = false; },
  };
}

/* ── Upload app ────────────────────────────── */
function uploadApp() {
  return {
    dragging: false,
    file: null,
    progress: 0,
    uploading: false,
    error: '',
    name: '',
    version: '',
    description: '',
    category: 'utility',
    installArgs: '',

    onDrop(e) {
      this.dragging = false;
      const f = e.dataTransfer?.files?.[0];
      if (f) this.file = f;
    },

    onFileSelect(e) {
      this.file = e.target.files?.[0] || null;
    },

    async upload() {
      if (!this.file || !this.name || !this.version) {
        this.error = 'File, name and version are required.';
        return;
      }
      this.uploading = true;
      this.error = '';
      this.progress = 0;
      const fd = new FormData();
      fd.append('file', this.file);
      fd.append('name', this.name);
      fd.append('version', this.version);
      fd.append('description', this.description);
      fd.append('category', this.category);
      fd.append('install_args', this.installArgs);

      const xhr = new XMLHttpRequest();
      xhr.upload.addEventListener('progress', e => {
        if (e.lengthComputable) this.progress = Math.round(e.loaded / e.total * 100);
      });
      xhr.onload = () => {
        this.uploading = false;
        if (xhr.status === 200) { window.location.reload(); }
        else { this.error = 'Upload failed. Please try again.'; }
      };
      xhr.onerror = () => { this.uploading = false; this.error = 'Network error.'; };
      xhr.open('POST', '/apps/upload');
      xhr.setRequestHeader('X-CSRFToken', getCsrfToken());
      xhr.send(fd);
    },
  };
}

/* ── Add user panel ────────────────────────── */
function addUserPanel(endpointId) {
  return {
    open: false,
    endpointId,
    username: '',
    fullName: '',
    description: '',
    isAdmin: false,
    autoPassword: true,
    password: '',
    mustChange: true,
    loading: false,
    error: '',

    show() { this.open = true; },
    close() { this.open = false; },

    generatePassword() {
      const groups = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghjkmnpqrstuvwxyz', '23456789', '!@#$%&*_-'];
      const all = groups.join('');
      const pick = chars => {
        const value = new Uint32Array(1);
        crypto.getRandomValues(value);
        return chars[value[0] % chars.length];
      };
      const password = groups.map(pick);
      while (password.length < 20) password.push(pick(all));
      for (let i = password.length - 1; i > 0; i -= 1) {
        const value = new Uint32Array(1);
        crypto.getRandomValues(value);
        const j = value[0] % (i + 1);
        [password[i], password[j]] = [password[j], password[i]];
      }
      this.password = password.join('');
    },

    async submit() {
      this.loading = true;
      this.error = '';
      if (this.autoPassword) this.generatePassword();
      try {
        const data = await wardenFetchJSON(`/endpoints/${this.endpointId}/users`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({
            username: this.username, full_name: this.fullName,
            description: this.description, is_admin: this.isAdmin,
            password: this.password, must_change: this.mustChange,
          }),
        });
        if (data.error) { this.error = data.error; }
        else { this.close(); window.location.reload(); }
      } catch (e) {
        this.error = 'Failed to dispatch job.';
      } finally {
        this.loading = false;
      }
    },
  };
}

/* ── Metric bar color helper ───────────────── */
function metricBarClass(pct) {
  if (pct < 70) return 'metric-bar-low';
  if (pct < 90) return 'metric-bar-mid';
  return 'metric-bar-high';
}

/* ── CSRF token helper ─────────────────────── */
function getCsrfToken() {
  return document.querySelector('meta[name=csrf-token]')?.content || '';
}

/* ── Activity-aware authentication renewal ───
   Access JWTs are intentionally short lived. Renew them only while the user
   is active; genuine inactivity still signs the browser out. localStorage
   shares activity timestamps across Warden tabs, and Web Locks prevents two
   tabs from rotating the same refresh token at once. */
function startSessionActivityMonitor() {
  const idleMeta = document.querySelector('meta[name=session-idle-minutes]');
  const accessMeta = document.querySelector('meta[name=access-token-minutes]');
  if (!idleMeta || !accessMeta) return; // unauthenticated/non-application page

  const idleMs = Math.max(1, Number(idleMeta.content) || 15) * 60 * 1000;
  const accessMs = Math.max(1, Number(accessMeta.content) || 15) * 60 * 1000;
  const refreshEveryMs = Math.max(60 * 1000, Math.floor(accessMs / 3));
  const activityKey = 'warden.auth.lastActivity.v1';
  const refreshKey = 'warden.auth.lastRefresh.v1';
  let lastRecorded = 0;
  let signingOut = false;

  const storedNumber = key => {
    const value = Number(localStorage.getItem(key));
    return Number.isFinite(value) ? value : 0;
  };
  const recordActivity = () => {
    const now = Date.now();
    if (now - lastRecorded < 10000) return;
    lastRecorded = now;
    localStorage.setItem(activityKey, String(now));
  };

  // Rendering an authenticated page proves this is a live session (including
  // the first page after a fresh login), so establish a new activity baseline.
  recordActivity();
  ['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart'].forEach(eventName => {
    window.addEventListener(eventName, recordActivity, { capture: true, passive: true });
  });

  const signOutForIdle = async () => {
    if (signingOut) return;
    signingOut = true;
    try {
      await fetch('/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken() },
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch (_) {
      // Navigation still clears the expired access-token experience even if
      // the network disappeared at the exact idle boundary.
    }
    window.location.assign('/login?reason=idle');
  };

  const refreshIfActive = async () => {
    const now = Date.now();
    if (now - storedNumber(activityKey) >= idleMs) {
      await signOutForIdle();
      return;
    }
    if (now - storedNumber(refreshKey) < refreshEveryMs) return;

    const rotate = async () => {
      const lockedNow = Date.now();
      if (lockedNow - storedNumber(refreshKey) < refreshEveryMs) return;
      const response = await fetch('/auth/refresh', {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken(), 'Accept': 'application/json' },
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (response.ok) {
        localStorage.setItem(refreshKey, String(Date.now()));
      } else if (response.status === 401) {
        window.location.assign('/login');
      }
    };

    try {
      if (navigator.locks?.request) {
        await navigator.locks.request('warden-auth-refresh', { ifAvailable: true }, async lock => {
          if (lock) await rotate();
        });
      } else {
        await rotate();
      }
    } catch (_) {
      // A temporary refresh failure must not interrupt current work; the next
      // scheduled attempt retries while the access token is still valid.
    }
  };

  window.setInterval(refreshIfActive, Math.min(60000, refreshEveryMs));
  window.setInterval(() => {
    if (Date.now() - storedNumber(activityKey) >= idleMs) signOutForIdle();
  }, 15000);
  refreshIfActive();
}

/* ── Flash auto-dismiss ───────────────────────
   Called from base.html's x-init instead of an inline arrow function —
   the CSP-safe Alpine parser can't parse function literals inline. */
function autoDismissFlash(el) {
  setTimeout(() => el.remove(), 5000);
}
window.autoDismissFlash = autoDismissFlash;

/* ── Toast notifications ───────────────────────
   Called as wardenToast(message, type) from many places (job dispatch,
   compliance scans, schedules) — reuses the same .flash markup/styling
   base.html renders server-side flashes with, just appended client-side
   into #app-flash and auto-dismissed. */
function wardenToast(message, type) {
  const container = document.getElementById('app-flash');
  if (!container) return;
  const category = type === 'error' ? 'error' : (type === 'warning' ? 'warning' : (type === 'info' ? 'info' : 'success'));
  const el = document.createElement('div');
  el.className = `flash flash-${category} fade-in`;
  const span = document.createElement('span');
  span.className = 'flex-1';
  span.textContent = message;
  const btn = document.createElement('button');
  btn.className = 'opacity-50 hover:opacity-100';
  btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>';
  btn.addEventListener('click', () => el.remove());
  el.appendChild(span);
  el.appendChild(btn);
  container.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}
window.wardenToast = wardenToast;

/* ── Time ago helper ───────────────────────── */
function timeAgo(isoStr) {
  const diff = Date.now() - new Date(isoStr);
  const secs = Math.floor(diff / 1000);
  if (secs < 60)  return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/* ── Copy to clipboard ─────────────────────── */
function copyToClipboard(text, buttonEl) {
  navigator.clipboard.writeText(text).then(() => {
    if (buttonEl) {
      const original = buttonEl.textContent;
      buttonEl.textContent = 'Copied!';
      setTimeout(() => { buttonEl.textContent = original; }, 1500);
    }
  }).catch(() => {});
}

/* ── Alpine CSP-build component registration ──
   The CSP-safe Alpine build (see server/Dockerfile) can't evaluate a bare
   x-data="wardenApp()" call expression — CSP builds only recognize names
   registered via Alpine.data(), referenced in HTML without parentheses
   (x-data="wardenApp"). Only these two components are actually used
   anywhere in the templates; the others above take constructor arguments
   the CSP build can't pass through x-data at all (they'd need to read
   params from data-* attributes instead) and aren't wired up yet. */
document.addEventListener('alpine:init', () => {
  Alpine.data('wardenApp', wardenApp);
  Alpine.data('slidePanel', slidePanel);
  Alpine.data('policyTemplateBuilder', policyTemplateBuilder);
  Alpine.data('installerModal', installerModal);
  Alpine.data('endpointDetail', endpointDetail);
  Alpine.data('compliancePage', compliancePage);
  Alpine.data('scheduledJobsPage', scheduledJobsPage);
  Alpine.data('securitySettingsPage', securitySettingsPage);
  Alpine.data('uploadModal', uploadModal);
  Alpine.data('enrollmentTokenForm', enrollmentTokenForm);
  Alpine.data('enrollmentProfileForm', enrollmentProfileForm);
  Alpine.data('passwordChangeForm', passwordChangeForm);
  Alpine.data('notificationPrefsForm', notificationPrefsForm);
  Alpine.data('thresholdsForm', thresholdsForm);
  Alpine.data('escalationCard', escalationCard);
  Alpine.data('usersListPage', usersListPage);
  Alpine.data('directoryPage', directoryPage);
  Alpine.data('adminProfileForm', adminProfileForm);
  Alpine.data('alertResolveWidget', alertResolveWidget);
  Alpine.data('patchManagementPage', patchManagementPage);
  Alpine.data('firewallPolicyPage', firewallPolicyPage);
  Alpine.data('topologyPage', topologyPage);
  Alpine.data('homeSpaceForm', () => ({ spaceType: 'home' }));
});

/* ── HTMX global config ────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  startSessionActivityMonitor();
  const routeProgress = document.getElementById('route-progress');
  const startProgress = () => routeProgress?.classList.add('is-active');
  const stopProgress = () => routeProgress?.classList.remove('is-active');
  document.body.addEventListener('htmx:beforeRequest', startProgress);
  // Keep expanded alert details and keyboard focus stable while reading.
  document.body.addEventListener('htmx:beforeRequest', (event) => {
    const snapshot = document.getElementById('stats-container');
    if (snapshot && event.detail.elt === snapshot &&
        (snapshot.querySelector('details[open]') || snapshot.contains(document.activeElement))) {
      event.preventDefault();
      stopProgress();
    }
  });
  document.body.addEventListener('htmx:beforeSwap', (event) => {
    const snapshot = event.detail.target;
    if (snapshot?.id === 'stats-container' &&
        (snapshot.querySelector('details[open]') || snapshot.contains(document.activeElement))) {
      event.detail.shouldSwap = false;
    }
  });
  // Polling must not replace a focused confirmation form or close a receipt.
  document.body.addEventListener('htmx:beforeRequest', (event) => {
    const activity = document.getElementById('home-live-activity');
    if (activity && event.detail.elt === activity && activity.contains(document.activeElement)) {
      event.preventDefault();
    }
  });
  document.body.addEventListener('htmx:beforeSwap', (event) => {
    if (event.detail.target?.id !== 'home-live-activity') return;
    event.detail.target.dataset.openReceipts = JSON.stringify(
      Array.from(event.detail.target.querySelectorAll('article')).filter(a => a.querySelector('details')?.open)
        .map(a => a.querySelector('a[href^="/jobs/"]')?.getAttribute('href')));
  });
  document.body.addEventListener('htmx:afterSwap', (event) => {
    if (event.detail.target?.id !== 'home-live-activity') return;
    const open = JSON.parse(event.detail.target.dataset.openReceipts || '[]');
    event.detail.target.querySelectorAll('article').forEach(article => {
      const details = article.querySelector('details');
      if (details && open.includes(article.querySelector('a[href^="/jobs/"]')?.getAttribute('href'))) details.open = true;
    });
  });
  document.body.addEventListener('htmx:afterSettle', stopProgress);
  document.body.addEventListener('htmx:responseError', stopProgress);
  window.addEventListener('beforeunload', startProgress);

  // A small Material-style touch response on actionable controls. It is
  // decorative only and disabled automatically when reduced motion is set.
  document.addEventListener('pointerdown', (event) => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const control = event.target.closest('.btn,.nav-item,.mobile-tab-bar a,.mobile-tab-bar button,.header-icon-button,.command-trigger');
    if (!control || control.disabled) return;
    const rect = control.getBoundingClientRect();
    const ripple = document.createElement('i');
    ripple.className = 'tap-ripple';
    ripple.style.left = `${event.clientX - rect.left}px`;
    ripple.style.top = `${event.clientY - rect.top}px`;
    control.appendChild(ripple);
    ripple.addEventListener('animationend', () => ripple.remove(), { once: true });
  }, { passive: true });
  // Add CSRF token to all HTMX requests
  document.body.addEventListener('htmx:configRequest', e => {
    e.detail.headers['X-CSRFToken'] = getCsrfToken();
  });
});
