// Monotonic, bounded replay retention. Entries expire in insertion order;
// request handling never rescans the whole fleet's recent envelope registry.
export class EnvelopeRegistry {
  constructor({limit=500000,lifetime=60000,clock=()=>performance.now()}={}) {
    this.limit=limit;this.lifetime=lifetime;this.clock=clock;this.entries=new Map();
  }
  accept(id){
    const now=this.clock();
    for(const [key,until] of this.entries){if(until>now)break;this.entries.delete(key);}
    if(this.entries.has(id))throw new Error('Replayed envelope');
    if(this.entries.size>=this.limit){const error=new Error('Encrypted runtime busy');error.status=503;throw error;}
    this.entries.set(id,now+this.lifetime);
  }
}
