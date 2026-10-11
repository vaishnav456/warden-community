// JPEG full frames replace every older pending update. Deltas retain order.
export class RemoteFrameQueue {
  constructor(maxFrames = 12, maxBytes = 16 * 1024 * 1024) {
    this.maxFrames = maxFrames;
    this.maxBytes = maxBytes;
    this.frames = [];
    this.bytes = 0;
    this.awaitingFull = true;
  }
  get length() { return this.frames.length; }
  desynchronize() {
    this.frames.length = 0;
    this.bytes = 0;
    this.awaitingFull = true;
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
