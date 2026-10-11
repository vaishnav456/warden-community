// JPEG full frames replace every older pending update. Deltas retain order.
export class RemoteFrameQueue {
  constructor(maxFrames = 12, maxBytes = 16 * 1024 * 1024) {
    this.maxFrames = maxFrames;
    this.maxBytes = maxBytes;
    this.frames = [];
    this.bytes = 0;
    this.awaitingFull = true;
    this.generation = 0;
    this.streamGeneration = 0;
  }
  get length() { return this.frames.length; }
  desynchronize() {
    this.frames.length = 0;
    this.bytes = 0;
    this.awaitingFull = true;
    this.generation++;
    this.streamGeneration++;
  }
  push(frame) {
    if (!(frame instanceof ArrayBuffer) || frame.byteLength < 2) {
      this.desynchronize(); return false;
    }
    const type = new Uint8Array(frame, 0, 1)[0];
    if ((type !== 0 && type !== 1) || (type === 1 && frame.byteLength < 10) || frame.byteLength > this.maxBytes) {
      this.desynchronize(); return false;
    }
    if (type === 0) {
      this.frames.length = 0;
      this.bytes = 0;
      this.awaitingFull = false;
      this.generation++;
    } else if (this.awaitingFull) return false;
    if (this.frames.length >= this.maxFrames || this.bytes + frame.byteLength > this.maxBytes) {
      this.desynchronize(); return false;
    }
    this.frames.push(frame);
    this.bytes += frame.byteLength;
    return true;
  }
  take() {
    const frame = this.frames.shift();
    if (frame) this.bytes -= frame.byteLength;
    return frame;
  }
}

export function parseRemoteFrame(buffer) {
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength < 2) throw new Error('Invalid remote frame');
  const type = new Uint8Array(buffer, 0, 1)[0];
  if (type === 0) return { type, offset: 1 };
  if (type !== 1 || buffer.byteLength < 10) throw new Error('Invalid remote frame');
  const view = new DataView(buffer, 1, 8);
  const frame = { type, offset: 9, x: view.getUint16(0, true), y: view.getUint16(2, true),
    w: view.getUint16(4, true), h: view.getUint16(6, true) };
  if (!frame.w || !frame.h) throw new Error('Invalid remote rectangle');
  return frame;
}

// An asynchronous decoder may finish after a newer full frame or a stream
// reset. Generation checks discard obsolete deltas/errors, while stream resets
// invalidate every in-flight image. A same-stream full frame can still paint
// before the next queued full: dropping it too would starve a full-frame source
// that runs faster than decoding. Every decoded bitmap is released.
export class RemoteFrameRenderer {
  constructor({ queue = new RemoteFrameQueue(), decode, draw, onFrame = () => {}, onError = () => {} }) {
    this.queue = queue;
    this.decode = decode;
    this.draw = draw;
    this.onFrame = onFrame;
    this.onError = onError;
    this.pending = null;
  }
  reset() { this.queue.desynchronize(); }
  push(buffer) {
    if (!this.queue.push(buffer)) return this.pending || Promise.resolve();
    if (!this.pending) this.pending = this.drain().finally(() => { this.pending = null; });
    return this.pending;
  }
  async drain() {
    while (this.queue.length) {
      const generation = this.queue.generation, stream = this.queue.streamGeneration, buffer = this.queue.take();
      let bitmap;
      try {
        const frame = parseRemoteFrame(buffer);
        bitmap = await this.decode(buffer, frame);
        if (stream !== this.queue.streamGeneration || (generation !== this.queue.generation && frame.type !== 0)) continue;
        this.draw(bitmap, frame);
        this.onFrame();
      } catch (error) {
        if (generation === this.queue.generation) {
          this.queue.desynchronize();
          this.onError(error);
        }
      } finally {
        if (bitmap) bitmap.close();
      }
    }
  }
}

export function remoteViewportSize(width, height, devicePixelRatio, nativeWidth, nativeHeight) {
  if (![width, height, nativeWidth, nativeHeight].every(value => Number.isFinite(value) && value > 0)) return null;
  if (!Number.isInteger(nativeWidth) || !Number.isInteger(nativeHeight)) return null;
  const dpr = Number.isFinite(devicePixelRatio) && devicePixelRatio > 0 ? devicePixelRatio : 1;
  // Keep the encoded image's native aspect ratio within the displayed canvas
  // pixel bounds. This also avoids an agent treating one oversized dimension
  // as a request for an unnecessarily full-resolution frame.
  const scale = Math.min(1, width * dpr / nativeWidth, height * dpr / nativeHeight);
  const maxWidth = Math.max(1, nativeWidth - (scale < 1 ? 1 : 0));
  const maxHeight = Math.max(1, nativeHeight - (scale < 1 ? 1 : 0));
  return { w: Math.max(1, Math.min(maxWidth, Math.round(nativeWidth * scale))),
    h: Math.max(1, Math.min(maxHeight, Math.round(nativeHeight * scale))) };
}

// Pointer devices may produce hundreds of movements between display frames.
// Keep the latest position; buttons, keys and releases can flush it immediately.
export class RemotePointerSender {
  constructor({ send, requestFrame, cancelFrame }) {
    this.send = send;
    this.requestFrame = requestFrame;
    this.cancelFrame = cancelFrame;
    this.pending = null;
    this.frame = null;
  }
  push(position) {
    this.pending = { type: 'mousemove', x: position.x, y: position.y };
    if (this.frame === null) this.frame = this.requestFrame(() => {
      this.frame = null;
      this.flush();
    });
  }
  flush() {
    if (this.frame !== null) this.cancelFrame(this.frame);
    this.frame = null;
    const position = this.pending;
    this.pending = null;
    if (position) this.send(position);
  }
  reset() {
    if (this.frame !== null) this.cancelFrame(this.frame);
    this.frame = null;
    this.pending = null;
  }
}
