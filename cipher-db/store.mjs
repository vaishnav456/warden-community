import { cipherParts } from './crypto.mjs';
import {member,hex} from './integrity.mjs';
import {setImmediate as yieldTurn} from 'node:timers/promises';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function identifier(value) {
  if (typeof value !== 'string' || !uuid.test(value)) throw new Error('Invalid opaque identifier');
  return value;
}
function ciphertext(value) {
  cipherParts(value);
  return value;
}
function table(collection) { return 'warden_cipher."r_' + identifier(collection).replaceAll('-', '') + '"'; }
export class RevisionConflict extends Error {
  constructor() { super('Encrypted database revision changed'); }
}

// The injected connection implements transaction(callback) and query(sql, args).
// It carries only random IDs and ciphertext; no decryption is done in PostgreSQL.
export class PostgresCipherStore {
  constructor(connection, dataset) { this.connection = connection; this.dataset = identifier(dataset); }
  async head(independent=false) {
    const query=independent?this.connection.independentQuery:this.connection.query;
    const result=await query('SELECT revision,manifest FROM warden_cipher.head WHERE id=$1',[this.dataset]);
    if(result.rows.length!==1) throw new Error('Encrypted database not initialized');
    identifier(result.rows[0].revision);ciphertext(result.rows[0].manifest);
    return result.rows[0];
  }
  peekHead(){return this.head(true);}
  async peekStamp(){
    const result=await this.connection.independentQuery("SELECT revision,encode(sha256(convert_to(manifest,'UTF8')),'hex') AS digest FROM warden_cipher.head WHERE id=$1",[this.dataset]);
    if(result.rows.length!==1||!/^[a-f0-9]{64}$/.test(result.rows[0].digest))throw new Error('Invalid encrypted head');
    identifier(result.rows[0].revision);return {dataset:this.dataset,...result.rows[0]};
  }
  async records(collection,ids){
    for(const id of ids)identifier(id);
    const result=await this.connection.query('SELECT id,payload FROM '+table(collection)+' WHERE id=ANY($1::uuid[])',[ids]);
    return new Map(result.rows.map(row=>[identifier(row.id),ciphertext(row.payload)]));
  }
  async read() {
    return this.connection.transaction(async tx => {
      await tx.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');
      const result = await tx.query('SELECT revision, manifest FROM warden_cipher.head WHERE id=$1', [this.dataset]);
      if (result.rows.length !== 1) throw new Error('Encrypted database not initialized');
      const header = result.rows[0];
      identifier(header.revision); ciphertext(header.manifest);
      const collections = new Map();
      const unexpected=await tx.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname<>'information_schema' AND c.relkind IN('r','p','m','f') AND NOT(n.nspname='warden_cipher' AND c.relkind='r' AND (c.relname='head' OR c.relname ~ '^r_[0-9a-f]{32}$')) LIMIT 1");
      if(unexpected.rows.length)throw new Error('Unexpected persistent application relation');
      const names = await tx.query("SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='warden_cipher' AND c.relkind='r' AND c.relname ~ '^r_[0-9a-f]{32}$'");
      for (const {relname} of names.rows) {
        if (!/^r_[0-9a-f]{32}$/.test(relname)) throw new Error('Unexpected storage table');
        const hex = relname.slice(2);
        const id = identifier([hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-'));
        const rows = await tx.query('SELECT id, payload FROM ' + table(id));
        const records = new Map();
        for (const row of rows.rows) records.set(identifier(row.id), ciphertext(row.payload));
        collections.set(id, records);
      }
      return {revision:header.revision, manifest:header.manifest, collections};
    });
  }
  async auditSnapshot(capture){
    if(!this.connection.snapshot)throw new Error('Independent audit snapshot required');
    return this.connection.snapshot(async tx=>{
      // First snapshot read and expected digests are captured under the writer
      // mutex; afterwards writes can proceed while this stable snapshot scans.
      const expected=await capture(async()=>{
        const result=await tx.query('SELECT revision,manifest FROM warden_cipher.head WHERE id=$1',[this.dataset]);
        if(result.rows.length!==1)throw new Error('Missing encrypted head');
        identifier(result.rows[0].revision);ciphertext(result.rows[0].manifest);return result.rows[0];
      });
      const unexpected=await tx.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname<>'information_schema' AND c.relkind IN('r','p','m','f') AND NOT(n.nspname='warden_cipher' AND c.relkind='r' AND (c.relname='head' OR c.relname ~ '^r_[0-9a-f]{32}$')) LIMIT 1");
      if(unexpected.rows.length)throw new Error('Unexpected persistent relation');
      const names=(await tx.query("SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='warden_cipher' AND c.relkind='r' AND c.relname ~ '^r_[0-9a-f]{32}$'")).rows;
      const wanted=new Set(expected.map(item=>'r_'+identifier(item.id).replaceAll('-','')));
      if(names.length!==wanted.size||names.some(item=>!wanted.has(item.relname)))throw new Error('Storage table membership changed');
      for(const item of expected){
        await tx.query('DECLARE cipher_audit_cursor NO SCROLL CURSOR FOR SELECT id,payload FROM '+table(item.id));
        let count=0,sum=0n;
        for(;;){
          const batch=(await tx.query('FETCH FORWARD 256 FROM cipher_audit_cursor')).rows;
          if(!batch.length)break;
          for(const row of batch){
            if(typeof row.payload!=='string'||!row.payload.startsWith('wdb1:')||row.payload.length>192*1024*1024)throw new Error('Ciphertext required');
            // The authenticated digest binds every byte already validated at
            // startup/commit; scanning does not need to decode every envelope.
            sum+=member(identifier(row.id),row.payload);count++;
          }
          await yieldTurn();
        }
        await tx.query('CLOSE cipher_audit_cursor');
        if(count!==item.count||hex(sum)!==item.digest)throw new Error('Encrypted record integrity changed');
      }
      return true;
    });
  }
  async initialize(manifest, revision, collections) {
    identifier(revision); ciphertext(manifest);
    await this.connection.transaction(async tx => {
      // Exclusive creation deliberately refuses existing schemas and datasets.
      await tx.query('CREATE SCHEMA warden_cipher');
      await tx.query("CREATE TABLE warden_cipher.head(id uuid PRIMARY KEY, revision uuid NOT NULL, manifest text NOT NULL CHECK(manifest ~ '^wdb1:[A-Za-z0-9_-]+$'))");
      for (const [id, rows] of collections) {
        await tx.query("CREATE TABLE " + table(id) + "(id uuid PRIMARY KEY, payload text NOT NULL CHECK(payload ~ '^wdb1:[A-Za-z0-9_-]+$'))");
        let records=[],payloads=[];
        const flush=async()=>{await tx.query('INSERT INTO '+table(id)+' SELECT * FROM unnest($1::uuid[],$2::text[])',[records,payloads]);records=[];payloads=[];};
        for (const [record, payload] of rows) {
          records.push(identifier(record));payloads.push(ciphertext(payload));
          if(records.length>=128)await flush();
        }
        if(records.length)await flush();
      }
      await tx.query('INSERT INTO warden_cipher.head VALUES($1,$2,$3)', [this.dataset,revision,manifest]);
    });
  }
  async commit(expected, revision, manifest, changes) {
    identifier(expected); identifier(revision); ciphertext(manifest);
    await this.connection.transaction(async tx => {
      const head = await tx.query('SELECT revision FROM warden_cipher.head WHERE id=$1 FOR UPDATE', [this.dataset]);
      if (head.rows.length !== 1 || head.rows[0].revision !== expected) throw new RevisionConflict();
      const grouped=new Map();
      for(const change of changes){
        identifier(change.collection);identifier(change.id);
        if(!['put','delete'].includes(change.kind))throw new Error('Invalid storage change');
        if(change.kind==='put')ciphertext(change.payload);
        const key=change.collection+':'+change.kind;
        if(!grouped.has(key))grouped.set(key,[]);grouped.get(key).push(change);
      }
      for(const group of grouped.values())for(let offset=0;offset<group.length;offset+=128){
        const chunk=group.slice(offset,offset+128),name=table(chunk[0].collection),ids=chunk.map(change=>change.id);
        if(chunk[0].kind==='delete'){
          const result=await tx.query('DELETE FROM '+name+' WHERE id=ANY($1::uuid[]) RETURNING id',[ids]);
          if(result.rows.length!==ids.length)throw new Error('Encrypted record missing');
        }else await tx.query('INSERT INTO '+name+' SELECT * FROM unnest($1::uuid[],$2::text[]) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',[ids,chunk.map(change=>change.payload)]);
      }
      await tx.query('UPDATE warden_cipher.head SET revision=$2,manifest=$3 WHERE id=$1', [this.dataset,revision,manifest]);
    });
  }
}

// Synthetic tests only. Production must provide a durable, transactional store.
export class MemoryCipherStore {
  async head() {
    if(!this.state) throw new Error('Encrypted database not initialized');
    return {revision:this.state.revision,manifest:this.state.manifest};
  }
  async read() {
    if (!this.state) throw new Error('Encrypted database not initialized');
    return structuredClone(this.state);
  }
  async initialize(manifest, revision, collections) {
    if (this.state) throw new Error('Encrypted database already initialized');
    this.state = structuredClone({manifest:ciphertext(manifest), revision:identifier(revision), collections});
  }
  async commit(expected, revision, manifest, changes) {
    if (!this.state || this.state.revision !== expected) throw new RevisionConflict();
    const next = await this.read();
    for (const change of changes) {
      const rows = next.collections.get(identifier(change.collection));
      if (!rows) throw new Error('Unknown encrypted collection');
      if (change.kind === 'delete') {
        if (!rows.delete(identifier(change.id))) throw new Error('Encrypted record missing');
      } else if (change.kind === 'put') rows.set(identifier(change.id), ciphertext(change.payload));
      else throw new Error('Invalid storage change');
    }
    next.revision = identifier(revision); next.manifest = ciphertext(manifest);
    this.state = next;
  }
}
