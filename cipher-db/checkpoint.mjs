import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';

export function stamp(dataset, state) {
  return {dataset, revision:state.revision, digest:createHash('sha256').update(state.manifest).digest('hex')};
}
function equal(a,b) { return JSON.stringify(a) === JSON.stringify(b); }
export class CheckpointMismatch extends Error {
  constructor() { super('Encrypted database checkpoint mismatch'); }
}
export class MemoryCheckpoint {
  async verify(actual) {
    if (this.pending) {
      if (equal(actual,this.pending.after)) this.head = actual;
      else if (!equal(actual,this.pending.before)) throw new CheckpointMismatch();
      this.pending = null;
    }
    if (!equal(actual,this.head)) throw new CheckpointMismatch();
  }
  async prepare(before,after) {
    if (this.pending || !equal(before,this.head)) throw new CheckpointMismatch();
    this.pending = {before,after};
  }
  async finish(after) {
    if (!this.pending || !equal(after,this.pending.after)) throw new CheckpointMismatch();
    this.head = after; this.pending = null;
  }
}

// Store outside the database, in the operator's private runtime directory.
// Neither these files nor their directory contain a key or business record.
export class FileCheckpoint {
  constructor(path) {
    if (!isAbsolute(path)) throw new Error('Absolute checkpoint path required');
    this.path = path;
  }
  async read(path) {
    try {
      const file = await open(path,'r');
      try {
        if ((await file.stat()).size > 2048) throw new CheckpointMismatch();
        return JSON.parse(await file.readFile('utf8'));
      } finally { await file.close(); }
    } catch (error) { if (error.code==='ENOENT') return undefined; throw error; }
  }
  async directorySync() {
    if (process.platform==='win32') throw new Error('Durable runtime checkpoints require Linux');
    const directory = await open(dirname(this.path),'r');
    try { await directory.sync(); } finally { await directory.close(); }
  }
  async write(path,value,exclusive=false,syncDirectory=true) {
    const file = await open(path,exclusive?'wx':'w',0o600);
    try { await file.writeFile(JSON.stringify(value)); await file.sync(); }
    finally { await file.close(); }
    if(syncDirectory)await this.directorySync();
  }
  async verify(actual) {
    const pending = await this.read(this.path+'.pending');
    if (pending) {
      if (equal(actual,pending.after)) await this.finish(actual);
      else if (equal(actual,pending.before)) {
        await unlink(this.path+'.pending');
      } else throw new CheckpointMismatch();
    }
    if (!equal(actual,await this.read(this.path))) throw new CheckpointMismatch();
  }
  async prepare(before,after) {
    await mkdir(dirname(this.path),{recursive:true,mode:0o700});
    if (!equal(before,await this.read(this.path))) throw new CheckpointMismatch();
    await this.write(this.path+'.pending',{before,after},true);
  }
  async finish(after) {
    const pending = await this.read(this.path+'.pending');
    if (!pending || !equal(after,pending.after)) throw new CheckpointMismatch();
    const temporary = this.path+'.'+randomUUID()+'.tmp';
    await this.write(temporary,after,true,false);
    await rename(temporary,this.path); await this.directorySync();
    // If a crash resurrects this unlink, verify() reconciles the same completed
    // after stamp. The durable head rename already establishes the commit.
    await unlink(this.path+'.pending');
  }
}
