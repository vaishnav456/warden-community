const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../static/js/warden.js'), 'utf8');
const start = source.indexOf('function topologyPage()');
const end = source.indexOf('\nfunction ', start + 1);
const context = vm.createContext({
  DOMPoint: class {
    constructor(x, y) { this.x = x; this.y = y; }
    matrixTransform() { return this; }
  },
});
vm.runInContext(source.slice(start, end), context);
const page = context.topologyPage();
page.$refs = { canvas: { getScreenCTM: () => ({ inverse: () => ({}) }) } };
// Device placement and room drawing share the same coordinates, including
// positions to the left/top and beyond the former right/bottom edge.
for (const [x, y] of [[150, 175], [-25, -40], [50, 50]]) {
  const event = { clientX: x * 10, clientY: y * 6 };
  assert.equal(page.canvasPoint(event).x, x);
  assert.equal(page.svgPoint(event).y, y);
}
page.rooms = [{ x: -40, y: 130, width: 200, height: 30 }];
page.placements = [{ x: 250, y: -20 }];
page.nodes = [{ x: -100, y: 200 }];
page.updateCanvasView = () => {};
page.fitAll();
const box = page.canvasViewBox().split(' ').map(Number);
assert.ok(box[0] <= -1070 && box[1] <= -162);
assert.ok(box[0] + box[2] >= 2570 && box[1] + box[3] >= 1242);
assert.ok(page.canvasZoom < 0.5);
console.log('Expandable coordinates and fit-all tests passed');
