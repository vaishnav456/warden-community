import {readFile} from 'node:fs/promises';
import {request} from 'node:http';
try{
  const token=(await readFile(process.env.CIPHER_TOKEN_FILE,'utf8')).trim();
  await new Promise((resolve,reject)=>{
    const req=request({socketPath:process.env.CIPHER_SOCKET,path:'/health',headers:{Authorization:'Bearer '+token}},res=>{
      res.resume();res.on('end',()=>res.statusCode===200?resolve():reject());});
    req.setTimeout(5000,()=>req.destroy());req.on('error',reject);req.end();
  });
}catch{process.exitCode=1;}
