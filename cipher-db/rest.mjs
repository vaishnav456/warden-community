// Warden's PostgREST-shaped application requests are compiled to parameterized
// SQL inside the trusted, in-memory application runtime. No SQL or clear rows
// are sent to the persistent database. Unsupported syntax is rejected.
const q=value=>'"'+value.replaceAll('"','""')+'"';
const ident=value=>{if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error('Invalid identifier');return q(value);};
const lit=value=>"'"+value.replaceAll("'","''")+"'";
function split(value) {
  const values=[];let start=0,depth=0,quoted=false,escaped=false;
  for(let i=0;i<value.length;i++) {
    const c=value[i];
    if(escaped){escaped=false;continue;}
    if(c==='\\' && quoted){escaped=true;continue;}
    if(c==='"'){quoted=!quoted;continue;}
    if(!quoted){if(c==='(')depth++;if(c===')')depth--;if(depth<0)throw new Error('Unbalanced expression');
      if(c===',' && !depth){values.push(value.slice(start,i));start=i+1;}}
  }
  if(depth||quoted)throw new Error('Unbalanced expression');
  values.push(value.slice(start));return values;
}
const unquote=value=>value.startsWith('"')?JSON.parse(value):value;
export class RestCompiler {
  constructor(engine){this.engine=engine;}
  async metadata(tx) {
    if(this.catalog) return this.catalog;
    const columns=(await tx.query(`SELECT n.nspname AS schema,c.relname AS name,a.attname AS column,
      format_type(a.atttypid,a.atttypmod) AS type,a.attgenerated AS generated
      FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='endpt' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`)).rows;
    const tables=new Map();for(const column of columns) {
      if(!tables.has(column.name))tables.set(column.name,{schema:column.schema,name:column.name,columns:new Map()});
      tables.get(column.name).columns.set(column.column,column);
    }
    const primary=(await tx.query(`SELECT c.relname AS name,ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(num,pos)
      JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.num ORDER BY pos)::text[] AS columns
      FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE i.indisprimary AND n.nspname='endpt'`)).rows;
    for(const item of primary)tables.get(item.name).pk=item.columns;
    const fks=(await tx.query(`SELECT con.conname AS name,src.relname AS source,dst.relname AS target,
      ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY k(num,pos) JOIN pg_attribute a ON a.attrelid=src.oid AND a.attnum=k.num ORDER BY pos)::text[] AS source_columns,
      ARRAY(SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY k(num,pos) JOIN pg_attribute a ON a.attrelid=dst.oid AND a.attnum=k.num ORDER BY pos)::text[] AS target_columns
      FROM pg_constraint con JOIN pg_class src ON src.oid=con.conrelid JOIN pg_class dst ON dst.oid=con.confrelid
      JOIN pg_namespace ns ON ns.oid=src.relnamespace JOIN pg_namespace nd ON nd.oid=dst.relnamespace
      WHERE con.contype='f' AND ns.nspname='endpt' AND nd.nspname='endpt'`)).rows;
    const routines=(await tx.query(`SELECT p.proname AS name,p.proretset AS set,p.proargnames AS names,p.provolatile AS volatility,
      p.pronargs AS nargs,p.pronargdefaults AS defaults,p.prorettype::regtype::text AS returns,
      ARRAY(SELECT t::regtype::text FROM unnest(p.proargtypes::oid[]) AS t) AS types
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='endpt' AND p.prokind='f'`)).rows;
    this.catalog={tables,fks,routines};return this.catalog;
  }
  parse(request) {
    if(!request||request.schema!=='endpt'||!['GET','HEAD','POST','PATCH','DELETE'].includes(request.method)||typeof request.path!=='string'||request.path.length>65536) throw new Error('Unsupported request');
    const url=new URL(request.path,'http://private.invalid/');
    if(url.origin!=='http://private.invalid'||url.hash)throw new Error('Invalid application path');
    const name=url.pathname.slice(1),dataJson=request.data_json??JSON.stringify(request.data),data=dataJson===undefined?undefined:JSON.parse(dataJson);
    if(name.startsWith('rpc/')&&(request.method!=='POST'||url.search))throw new Error('Unsupported routine request');
    return {...request,url,name,dataJson,data};
  }
  async request(input) {
    const request=this.parse(input),{name,data}=request;
    let routine;
    if(name.startsWith('rpc/')) {
      // Routine volatility comes from the server's SQL catalog, never from
      // caller flags. Warm a cold catalog through a read-only transaction so
      // the first dashboard aggregate also avoids the durable writer queue.
      const catalog=this.catalog??await this.engine.application(tx=>this.metadata(tx),{readOnly:true});
      routine=this.routine(catalog,name.slice(4),data);
    }
    return this.engine.application(async tx=>this.executeRequest(tx,request,await this.metadata(tx),routine),
      {readOnly:request.method==='GET'||request.method==='HEAD'||['s','i'].includes(routine?.volatility)});
  }
  async requestBatch(inputs) {
    if(!Array.isArray(inputs)||inputs.length<1||inputs.length>8)throw new Error('Invalid application batch');
    const requests=Array.from(inputs,input=>this.parse(input));
    // A batch is one durable application transaction. The engine owns commit,
    // constraints and rollback; an operation error must abort every operation.
    return this.engine.application(async tx=>{
      const catalog=await this.metadata(tx),results=[];
      for(const request of requests)results.push(await this.executeRequest(tx,request,catalog));
      return results;
    },{readOnly:false});
  }
  async executeRequest(tx,request,catalog,resolvedRoutine) {
      const {name,url,dataJson,data}=request,params=[],bind=value=>{params.push(value);return '$'+params.length;};
      if(name.startsWith('rpc/')) {
        const fn=name.slice(4),body=data,routine=resolvedRoutine??this.routine(catalog,fn,body);
        const payload=Object.keys(body).length?bind(dataJson):undefined;
        const arguments_=Object.keys(body).map(k=>ident(k)+'=>'+this.typed(payload,routine.types[routine.names.indexOf(k)],k));
        const call=ident('endpt')+'.'+ident(fn)+'('+arguments_.join(',')+')';
        const composite=catalog.tables.has(routine.returns.replace(/^endpt\./,''))||routine.returns==='record';
        const sql=routine.set||composite?'SELECT COALESCE(json_agg(r),\'[]\'::json)::text AS body FROM '+call+' r':
          'SELECT to_json('+call+')::text AS body';
        const result=await tx.query(sql,params);return {status:200,body:result.rows[0].body??'null',headers:{}};
      }
      const table=catalog.tables.get(name);if(!table)throw new Error('Unknown application table');
      const ref=ident(table.schema)+'.'+ident(table.name),query=url.searchParams;
      for(const key of ['select','order','limit','offset','on_conflict'])if(query.getAll(key).length>1)throw new Error('Duplicate request option');
      const filters=this.filters(table,'r','',query,catalog,bind);
      const preferred=new Set((request.prefer||'').split(','));
      if(request.method==='GET'||request.method==='HEAD') {
        const selected=this.selection(table,'r',query.get('select')||'*','',query,catalog,bind);
        const where=[...filters,...selected.inner];
        const clause=where.length?' WHERE '+where.join(' AND '):'';
        const countSql='SELECT count(*)::text AS total FROM '+ref+' r'+clause;
        if(request.method==='HEAD')return {status:200,body:'',headers:{'Content-Range':'*/'+(await tx.query(countSql,params)).rows[0].total}};
        const order=this.order(table,'r',query.get('order'));
        const limit=this.integer(query.get('limit'),1000),offset=this.integer(query.get('offset'),0);
        const sql='SELECT COALESCE(json_agg(row_value),\'[]\'::json)::text AS body FROM (SELECT '+selected.sql+' AS row_value FROM '+ref+' r'+clause+order+
          ' LIMIT '+limit+' OFFSET '+offset+') page';
        const result=await tx.query(sql,params),body=result.rows[0].body;
        const n=JSON.parse(body).length;
        const total=preferred.has('count=exact')?(await tx.query(countSql,params)).rows[0].total:'*';
        return {status:200,body,headers:{'Content-Range':(n?offset+'-'+(offset+n-1):'*')+'/'+total}};
      }
      if(request.method!=='POST' && !filters.length)throw new Error('Unbounded mutation rejected');
      let mutation;
      if(request.method==='POST') {
        const rows=Array.isArray(data)?data:[data];
        if(!rows.length)return {status:201,body:preferred.has('return=minimal')?'':'[]',headers:{}};
        if(rows.some(row=>!row||typeof row!=='object'||Array.isArray(row)))throw new Error('Invalid write data');
        const columns=Object.keys(rows[0]);
        if(!columns.length||rows.some(row=>Object.keys(row).length!==columns.length||columns.some(c=>!Object.hasOwn(row,c))))throw new Error('Inconsistent write columns');
        for(const c of columns)this.column(table,c,true);
        const payload=bind(Array.isArray(data)?dataJson:'['+dataJson+']');
        const conflict=query.get('on_conflict')||table.pk.join(',');let suffix='';
        if(preferred.has('resolution=merge-duplicates')||preferred.has('resolution=ignore-duplicates')) {
          if(!conflict)throw new Error('Conflict columns required');
          const targets=split(conflict);for(const c of targets)this.column(table,c);
          suffix=' ON CONFLICT('+targets.map(ident).join(',')+') DO '+(preferred.has('resolution=ignore-duplicates')?'NOTHING':
            'UPDATE SET '+columns.map(c=>ident(c)+'=excluded.'+ident(c)).join(','));
        } else if(query.has('on_conflict'))throw new Error('Conflict resolution required');
        mutation='INSERT INTO '+ref+'('+columns.map(ident).join(',')+') SELECT '+columns.map(ident).join(',')+
          ' FROM json_populate_recordset(NULL::'+ref+','+payload+'::json)'+suffix;
      } else if(request.method==='PATCH') {
        if(!data||Array.isArray(data)||typeof data!=='object'||!Object.keys(data).length)throw new Error('Invalid write data');
        const payload=bind(dataJson);
        mutation='UPDATE '+ref+' r SET '+Object.keys(data).map(c=>ident(c)+'='+this.typed(payload,this.column(table,c,true).type,c)).join(',')+
          ' WHERE '+filters.join(' AND ');
      } else mutation='DELETE FROM '+ref+' r WHERE '+filters.join(' AND ');
      const result=await tx.query('WITH changed AS ('+mutation+' RETURNING *) SELECT COALESCE(json_agg(changed),\'[]\'::json)::text AS body FROM changed',params);
      const minimal=request.method==='DELETE'||(request.method==='PATCH'&&!preferred.has('return=representation'))||preferred.has('return=minimal');
      return {status:request.method==='POST'?201:200,body:minimal?'':result.rows[0].body,headers:{}};
  }
  routine(catalog,name,body) {
    if(!body||Array.isArray(body)||typeof body!=='object')throw new Error('Invalid routine arguments');
    const candidates=catalog.routines.filter(r=>r.name===name && Object.keys(body).every(k=>r.names?.slice(0,r.nargs).includes(k)) &&
      (r.names||[]).slice(0,r.nargs-r.defaults).every(k=>Object.hasOwn(body,k)));
    if(candidates.length!==1){const error=new Error('Ambiguous or unknown routine');error.code='PGRST202';error.status=404;throw error;}
    return candidates[0];
  }
  integer(value,fallback){if(value===null)return fallback;if(!/^\d+$/.test(value)||Number(value)>1000000000)throw new Error('Invalid pagination');return Number(value);}
  column(table,name,write=false){const c=table.columns.get(name);if(!c||(write&&c.generated))throw new Error('Unknown or generated column');return c;}
  typed(parameter,type,field='v') {
    // Type names originate in the authenticated SQL catalog, never the request.
    return '(SELECT v.'+ident(field)+' FROM json_to_record('+parameter+'::json) AS v('+ident(field)+' '+type+'))';
  }
  value(table,alias,name){this.column(table,name);return ident(alias)+'.'+ident(name);}
  order(table,alias,value){if(!value)return '';return ' ORDER BY '+split(value).map(item=>{
    const [column,direction='asc',nulls]=item.split('.');
    if(!['asc','desc'].includes(direction)||nulls&&!['nullsfirst','nullslast'].includes(nulls))throw new Error('Invalid ordering');
    return this.value(table,alias,column)+' '+direction+(nulls?' NULLS '+(nulls==='nullsfirst'?'FIRST':'LAST'):'');
  }).join(',');}
  predicate(table,alias,column,expression,bind) {
    const field=this.value(table,alias,column);let negate=false;
    if(expression.startsWith('not.')){negate=true;expression=expression.slice(4);}
    const position=expression.indexOf('.');if(position<1)throw new Error('Invalid filter');
    const op=expression.slice(0,position),value=expression.slice(position+1);let sql;
    if(op==='is'){if(!['null','true','false','unknown'].includes(value))throw new Error('Invalid null filter');sql=field+' IS '+value;}
    else if(op==='in'){
      if(!value.startsWith('(')||!value.endsWith(')'))throw new Error('Invalid set filter');
      const members=split(value.slice(1,-1));sql=field+' IN ('+members.map(v=>bind(unquote(v))).join(',')+')';
    } else {
      const operators={eq:'=',neq:'<>',gt:'>',gte:'>=',lt:'<',lte:'<=',like:'LIKE',ilike:'ILIKE',cs:'@>',cd:'<@',ov:'&&'};
      if(!Object.hasOwn(operators,op))throw new Error('Unsupported filter operator');
      const now=value==='now()'&&this.column(table,column).type.startsWith('timestamp')&&['eq','neq','gt','gte','lt','lte'].includes(op);
      sql=field+' '+operators[op]+' '+(now?'now()':bind(op==='like'||op==='ilike'?value.replaceAll('*','%'):value));
    }
    return negate?'NOT ('+sql+')':sql;
  }
  logical(table,alias,expression,bind) {
    return split(expression).map(item=>{
      const group=/^(not\.)?(or|and)\((.*)\)$/.exec(item);
      if(group)return (group[1]?'NOT ':'')+'('+this.logical(table,alias,group[3],bind).join(group[2]==='or'?' OR ':' AND ')+')';
      const index=item.indexOf('.');if(index<1)throw new Error('Invalid logical expression');
      return this.predicate(table,alias,item.slice(0,index),item.slice(index+1),bind);
    });
  }
  filters(table,alias,prefix,query,catalog,bind){
    const clauses=[];
    for(const [name,expression] of query) {
      if(!name.startsWith(prefix))continue;const column=name.slice(prefix.length);
      if(['select','order','limit','offset','on_conflict'].includes(column)||column.includes('.')&&!column.startsWith('not.'))continue;
      if(['or','and','not.or','not.and'].includes(column)){
        if(!expression.startsWith('(')||!expression.endsWith(')'))throw new Error('Invalid logical group');
        clauses.push((column.startsWith('not.')?'NOT ':'')+'('+this.logical(table,alias,expression.slice(1,-1),bind).join(column.endsWith('or')?' OR ':' AND ')+')');
      } else clauses.push(this.predicate(table,alias,column,expression,bind));
    }return clauses;
  }
  selection(table,alias,selection,prefix,query,catalog,bind,depth=0) {
    if(depth>5)throw new Error('Selection nesting limit');
    const pairs=[],inner=[];let star=false;
    for(const part of split(selection)) {
      if(part==='*'){star=true;continue;}
      const embed=/^([A-Za-z_][\w:!]*?)\((.*)\)$/.exec(part);
      if(!embed){const names=part.split(':');if(names.length>2)throw new Error('Invalid projection');
        const column=names.at(-1);pairs.push(lit(names.length===2?names[0]:column),this.value(table,alias,column));continue;}
      const [label,nameWithHints]=embed[1].includes(':')?embed[1].split(':'):[null,embed[1]];
      const [name,...hints]=nameWithHints.split('!'),target=catalog.tables.get(name);if(!target)throw new Error('Unknown embedded relation');
      const hint=hints.find(h=>h!=='inner'&&h!=='left'),matches=catalog.fks.filter(f=>
        ((f.source===table.name&&f.target===name)||(f.target===table.name&&f.source===name))&&
        (!hint||f.name===hint||f.source_columns.includes(hint)));
      if(matches.length!==1)throw new Error('Ambiguous embedded relation');
      const fk=matches[0],forward=fk.source===table.name,childAlias='e'+depth+'_'+pairs.length;
      const childPrefix=prefix+(label||name)+'.';
      const selected=this.selection(target,childAlias,embed[2],childPrefix,query,catalog,bind,depth+1);
      const own=forward?fk.source_columns:fk.target_columns,other=forward?fk.target_columns:fk.source_columns;
      const conditions=own.map((col,i)=>this.value(table,alias,col)+'='+this.value(target,childAlias,other[i]));
      conditions.push(...this.filters(target,childAlias,childPrefix,query,catalog,bind),...selected.inner);
      const from=ident(target.schema)+'.'+ident(name)+' '+ident(childAlias)+' WHERE '+conditions.join(' AND ');
      const order=this.order(target,childAlias,query.get(childPrefix+'order'));
      const limit=query.has(childPrefix+'limit')?' LIMIT '+this.integer(query.get(childPrefix+'limit'),1000):'';
      const child='SELECT '+selected.sql+' AS value FROM '+from+order+(forward?' LIMIT 1':limit);
      pairs.push(lit(label||name),forward?'('+child+')':"(SELECT COALESCE(json_agg(value),'[]'::json) FROM ("+child+') embedded)');
      if(hints.includes('inner'))inner.push('EXISTS(SELECT 1 FROM '+from+')');
    }
    const base=star?'to_jsonb('+ident(alias)+')':"'{}'::jsonb";
    return {sql:pairs.length?base+' || jsonb_build_object('+pairs.join(',')+')':base,inner};
  }
}
