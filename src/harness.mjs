// Reviewed, source-pinned local Bastion protocol campaigns. No model, shell or HTTP traffic.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {sha,json} from './core.mjs';
const here=fileURLToPath(import.meta.url);
export const harnessScenarios=['verified-reuse','unapproved-refused','wrong-digest-refused','changed-input-refused','foreign-cursor-refused','report-tamper-refused','pending-cancel'];
const must=(ok,message)=>{if(!ok)throw Error(message);};
const readJSON=async file=>JSON.parse(await fs.readFile(file,'utf8'));
const identity=async()=>({adapter:sha(await fs.readFile(here)),core:sha(await fs.readFile(new URL('./core.mjs',import.meta.url)))});
async function pins(source){
 must(path.isAbsolute(source),'Absolute reviewed source required');
 must(await fs.realpath(source)===source,'Source must be canonical, not a symlink');
 const folder=path.join(source,'bastion');must(!(await fs.lstat(folder)).isSymbolicLink(),'Symlink source refused');
 const files={};let bytes=0;
 for(const name of (await fs.readdir(folder)).filter(n=>n.endsWith('.py')).sort()){
  const p=path.join(folder,name),s=await fs.lstat(p);must(s.isFile()&&!s.isSymbolicLink(),'Regular source files required');
  bytes+=s.size;must(bytes<=4*1024*1024&&Object.keys(files).length<100,'Source pin budget exceeded');files['bastion/'+name]=sha(await fs.readFile(p));
 }
 must(files['bastion/__main__.py']&&files['bastion/__init__.py'],'Bastion source entry points required');return files;
}
function validate(plan){
 must(plan?.schema==='whatif.harness-plan.v1'&&plan.adapter==='bastion-cli','Unsupported harness adapter');
 must(JSON.stringify(plan.scenarios)===JSON.stringify(harnessScenarios),'Scenario oracles cannot be replaced');
 const b=plan.budgets;must(b&&Object.keys(b).sort().join(',')==='maxCommands,maxOutputBytes,maxWallSeconds','Exact budgets required');
 for(const [key,lo,hi]of [['maxCommands',1,100],['maxOutputBytes',1024,1048576],['maxWallSeconds',1,120]])must(Number.isInteger(b[key])&&b[key]>=lo&&b[key]<=hi,'Invalid '+key);
}
export async function planHarness({source,python,out}){
 source=path.resolve(source);python=await fs.realpath(python);
 const plan={schema:'whatif.harness-plan.v1',adapter:'bastion-cli',source,sourcePins:await pins(source),python:{path:python,sha256:sha(await fs.readFile(python))},
  engine:await identity(),scenarios:harnessScenarios,budgets:{maxCommands:64,maxOutputBytes:1048576,maxWallSeconds:120},
  trust:'reviewed local Python with host permissions; not an OS sandbox',authority:'exact source acknowledgement plus plan digest; no provider or network authorization'};
 validate(plan);await fs.mkdir(out,{mode:0o700});await fs.writeFile(path.join(out,'plan.json'),json(plan),{flag:'wx'});
 return {directory:out,digest:sha(json(plan)),scenarios:plan.scenarios.length,execution:'not-started',trust:plan.trust};
}
async function current(plan){
 must(JSON.stringify(await pins(plan.source))===JSON.stringify(plan.sourcePins),'Harness source pins changed');
 must(sha(await fs.readFile(plan.python.path))===plan.python.sha256,'Python identity changed');
 must(JSON.stringify(await identity())===JSON.stringify(plan.engine),'WhatIF adapter identity changed');
}
async function command(plan,workspace,args,budget){
 await current(plan);must(budget.commands<plan.budgets.maxCommands,'Command budget exhausted');
 const remaining=budget.deadline-Date.now();must(remaining>0,'Campaign wall budget exhausted');
 return await new Promise((resolve,reject)=>{
  const bootstrap="import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('bastion',run_name='__main__')";
  const child=spawn(plan.python.path,['-I','-B','-c',bootstrap,plan.source,'--workspace',workspace,...args],{cwd:plan.source,env:{PATH:process.env.PATH??'/usr/bin:/bin',HOME:process.env.HOME??'',TMPDIR:process.env.TMPDIR??'/tmp',LANG:'C.UTF-8',PYTHONDONTWRITEBYTECODE:'1'},stdio:['ignore','pipe','pipe'],detached:true});
  budget.commands++;
  let stdout=[],stderr=[],failed=null;
  const kill=()=>{try{process.kill(-child.pid,'SIGKILL');}catch{}};
  const timer=setTimeout(()=>{failed=Error('Campaign wall budget exhausted');kill();},remaining);
  const capture=target=>data=>{if(failed)return;const remaining=plan.budgets.maxOutputBytes-budget.bytes;const kept=data.subarray(0,remaining);budget.bytes+=kept.length;target.push(kept);if(data.length>remaining){failed=Error('Campaign output budget exhausted');kill();}};
  child.stdout.on('data',capture(stdout));child.stderr.on('data',capture(stderr));child.on('error',e=>{failed=e;});
  child.on('close',code=>{clearTimeout(timer);kill();
   const out=Buffer.concat(stdout).toString(),err=Buffer.concat(stderr).toString();
   budget.evidence.push({args,workspace:path.basename(workspace),stdout:out,stderr:err,exitCode:code,error:failed?.message??null});
   budget.trace.push({evidence:budget.evidence.length-1,command:args[0]+(args[1]?' '+args[1]:''),exitCode:code,stdoutSha256:sha(out),stderrSha256:sha(err),error:failed?.message??null});
   if(failed)return reject(failed);let value;
   try{value=JSON.parse(code===0?out:(err||out));}catch{return reject(Error('Invalid harness JSON response'));}
   resolve({code,value});
  });
 });
}
export async function runHarness(directory,{ackSource,digest}){
 const plan=await readJSON(path.join(directory,'plan.json'));validate(plan);
 must(ackSource===plan.source,'Exact reviewed source acknowledgement required');must(digest===sha(json(plan)),'Reviewed plan digest mismatch');await current(plan);
 must(await fs.realpath(directory)===directory,'Canonical case directory required');
 await fs.writeFile(path.join(directory,'run-start.json'),json({planDigest:digest,startedAt:new Date().toISOString()}),{flag:'wx'});
 await fs.mkdir(path.join(directory,'fixtures'),{mode:0o700});
 const budget={commands:0,bytes:0,deadline:Date.now()+plan.budgets.maxWallSeconds*1000,trace:[],evidence:[]},outcomes=[];
 const workflow={schema:'bastion.workflow.v1',title:'WhatIF owned fixture',nodes:[{id:'sum',capability:'math.sum_u32',params:{values:[1,2,3]}}]};
 for(const name of plan.scenarios){
  const workspace=path.join(directory,'fixtures',name);await fs.mkdir(workspace,{mode:0o700});
  const call=(...args)=>command(plan,workspace,args,budget);
  const ok=async(...args)=>{const r=await call(...args);must(r.code===0,'Unexpected failure: '+JSON.stringify(r.value));return r.value;};
  const refused=async(pattern,...args)=>{const r=await call(...args);must(r.code!==0&&pattern.test(JSON.stringify(r.value)),'Expected specific refusal: '+JSON.stringify(r.value));return r.value;};
  let outcome={scenario:name,status:'unknown'};
  try{
   await fs.writeFile(path.join(workspace,'workflow.json'),json(workflow));
   if(name==='report-tamper-refused'){
    await fs.writeFile(path.join(workspace,'test_probe.py'),'import unittest\nclass Probe(unittest.TestCase):\n def test_sum(self): self.assertEqual(1+2+3,6)\n');
    const spec={recipe:'python-unittest',name:'WhatIF reviewed fixture',files:['test_probe.py'],testModules:['test_probe'],minTests:1,trust:'reviewed-local-code; not-os-sandboxed',budgets:{wallSeconds:10,cpuSeconds:5,outputBytes:65536,stateBytes:67108864}};
    await fs.writeFile(path.join(workspace,'task.json'),json(spec));const p=await ok('task','plan','task.json');await ok('task','approve',p.task,p.digest);const r=await ok('task','run',p.task,p.digest);must(r.passed,'Fixture tests did not pass');
    await fs.appendFile(path.join(workspace,'.bastion','checks',p.task,'output.log'),'deliberate WhatIF tamper');await refused(/log integrity/,'task','report',p.task);
   }else if(name==='foreign-cursor-refused'){
    const progress=await ok('progress');const other=path.join(workspace,'other');await fs.mkdir(other);const r=await command(plan,other,['progress','--cursor',progress.cursor],budget);must(r.code!==0&&/foreign/.test(JSON.stringify(r.value)),'Foreign cursor accepted');
   }else{
    if(name==='changed-input-refused'){
     await fs.writeFile(path.join(workspace,'brief.txt'),'original fixture');await fs.writeFile(path.join(workspace,'workflow.json'),json({schema:'bastion.workflow.v1',title:'pinned read',nodes:[{id:'ingest',capability:'knowledge.ingest',params:{path:'brief.txt'}}]}));
    }
    const p=await ok('plan','workflow.json');
    if(name==='unapproved-refused'){await refused(/invalid-transition/,'run',p.run,p.digest);const state=await ok('inspect',p.run);must(state.state==='draft'&&!state.approved,'Unapproved work changed state');}
    if(name==='wrong-digest-refused')await refused(/digest mismatch/,'approve',p.run,'0'.repeat(64));
    if(name==='changed-input-refused'){await fs.writeFile(path.join(workspace,'brief.txt'),'changed fixture');await refused(/input identity changed/,'approve',p.run,p.digest);}
    if(name==='verified-reuse'){
     await ok('approve',p.run,p.digest);const first=await ok('run',p.run,p.digest);must(first.receipt.outputs.sum===6,'Independent sum oracle failed');
     const verified=await ok('verify',p.run);const progress=await ok('progress');const reused=await ok('run',p.run,p.digest);const delta=await ok('progress','--cursor',progress.cursor);
     must(first.receiptDigest===verified.receiptDigest&&first.receiptDigest===reused.receiptDigest,'Receipt reuse mismatch');must(!delta.events.some(e=>e.kind==='node-started'),'Completed nodes re-executed');
    }
    if(name==='pending-cancel'){
     const spec={goal:'stop before work',jobs:[{kind:'workflow',run:p.run,digest:p.digest}],notBefore:0,deadline:Date.now()/1000+60,budgets:{maxJobs:1,maxAttempts:1,maxWallSeconds:30,maxOutputBytes:65536,maxStateBytes:67108864}};
     await fs.writeFile(path.join(workspace,'mission.json'),json(spec));const m=await ok('mission','plan','mission.json');await ok('mission','cancel',m.mission,m.digest,'--reason','WhatIF owned cancellation fixture');
     must((await ok('mission','work',m.mission,m.digest)).state==='cancelled','Stop not acknowledged');must((await ok('inspect',p.run)).state==='draft','Cancelled work executed');
    }
   }
   outcome.status='passed';
  }catch(error){outcome={...outcome,status:'failed',error:error.message};outcomes.push(outcome);break;}
  outcomes.push(outcome);
 }
 const results={schema:'whatif.harness-result.v1',planDigest:digest,planned:plan.scenarios.length,executed:outcomes.length,
  passed:outcomes.filter(x=>x.status==='passed').length,failed:outcomes.filter(x=>x.status==='failed').length,unknown:plan.scenarios.length-outcomes.length,
  outcomes,commands:budget.commands,outputBytes:budget.bytes,trace:budget.trace,scope:'real local CLI contracts on disposable fixtures; no hostile-code sandbox, live model, load or superiority claim'};
 await fs.writeFile(path.join(directory,'results.json'),json(results),{flag:'wx'});
 await fs.writeFile(path.join(directory,'command-evidence.json'),json(budget.evidence),{flag:'wx'});
 const files={};for(const name of ['plan.json','run-start.json','results.json','command-evidence.json'])files[name]=sha(await fs.readFile(path.join(directory,name)));
 await fs.writeFile(path.join(directory,'evidence-index.json'),json({schema:'whatif.harness-evidence.v1',files}),{flag:'wx'});
 return results;
}
export async function verifyHarness(directory){
 const index=await readJSON(path.join(directory,'evidence-index.json'));
 must(index.schema==='whatif.harness-evidence.v1'&&JSON.stringify(Object.keys(index.files).sort())===JSON.stringify(['command-evidence.json','plan.json','results.json','run-start.json']),'Evidence closure mismatch');
 for(const [name,hash]of Object.entries(index.files))must(sha(await fs.readFile(path.join(directory,name)))===hash,'Evidence hash mismatch: '+name);
 const plan=await readJSON(path.join(directory,'plan.json'));validate(plan);must(JSON.stringify(plan.engine)===JSON.stringify(await identity()),'Verifier adapter identity changed; use the retained version');const result=await readJSON(path.join(directory,'results.json'));const start=await readJSON(path.join(directory,'run-start.json'));
 must(result.planDigest===sha(json(plan))&&start.planDigest===result.planDigest,'Plan binding mismatch');
 must(Number.isInteger(result.executed)&&result.executed>=0&&result.executed<=plan.scenarios.length&&Number.isInteger(result.unknown)&&result.unknown>=0,'Invalid coverage range');
 must(result.executed===result.outcomes.length&&result.planned===plan.scenarios.length&&result.unknown===result.planned-result.executed,'Coverage mismatch');
 must(result.outcomes.every((r,i)=>r.scenario===plan.scenarios[i]&&['passed','failed'].includes(r.status)),'Scenario identity mismatch');
 must(result.passed===result.outcomes.filter(r=>r.status==='passed').length&&result.failed===result.outcomes.filter(r=>r.status==='failed').length,'Outcome count mismatch');
 must(Number.isInteger(result.commands)&&result.commands<=plan.budgets.maxCommands&&result.commands===result.trace.length&&result.outputBytes<=plan.budgets.maxOutputBytes,'Measured budget mismatch');
 const evidence=await readJSON(path.join(directory,'command-evidence.json'));
 must(evidence.length===result.trace.length,'Command evidence closure mismatch');
 for(const [i,step]of evidence.entries()){
  must(result.trace[i].evidence===i&&sha(step.stdout)===result.trace[i].stdoutSha256&&sha(step.stderr)===result.trace[i].stderrSha256&&step.exitCode===result.trace[i].exitCode,'Command evidence hash mismatch');
 }
 // Re-evaluate fixed assertions from retained responses, not the passed flag alone.
 let offset=0;
 for(const outcome of result.outcomes){
  if(outcome.status!=='passed')break;
  const count={'verified-reuse':7,'unapproved-refused':3,'wrong-digest-refused':2,'changed-input-refused':2,'foreign-cursor-refused':2,'report-tamper-refused':4,'pending-cancel':5}[outcome.scenario];
  const steps=evidence.slice(offset,offset+count);offset+=count;must(steps.length===count,'Scenario command evidence incomplete');
  const values=steps.map(step=>{try{return JSON.parse(step.exitCode===0?step.stdout:(step.stderr||step.stdout));}catch{throw Error('Scenario command JSON invalid');}});
  const fail=(i,pattern)=>steps[i].exitCode!==0&&pattern.test(JSON.stringify(values[i]));
  const success=i=>steps[i].exitCode===0;
  let passed=false;
  if(outcome.scenario==='verified-reuse')passed=steps.every((_,i)=>success(i))&&values[2].receipt?.outputs?.sum===6&&values[2].receiptDigest===values[3].receiptDigest&&values[2].receiptDigest===values[5].receiptDigest&&!values[6].events.some(e=>e.kind==='node-started');
  if(outcome.scenario==='unapproved-refused')passed=success(0)&&fail(1,/invalid-transition/)&&success(2)&&values[2].state==='draft'&&!values[2].approved;
  if(outcome.scenario==='wrong-digest-refused')passed=success(0)&&fail(1,/digest mismatch/)&&steps[1].args[2]==='0'.repeat(64);
  if(outcome.scenario==='changed-input-refused')passed=success(0)&&fail(1,/input identity changed/);
  if(outcome.scenario==='foreign-cursor-refused')passed=success(0)&&typeof values[0].cursor==='string'&&fail(1,/foreign/);
  if(outcome.scenario==='report-tamper-refused')passed=success(0)&&success(1)&&success(2)&&values[2].passed===true&&fail(3,/log integrity/);
  if(outcome.scenario==='pending-cancel')passed=steps.every((_,i)=>success(i))&&values[3].state==='cancelled'&&values[4].state==='draft';
  must(passed,'Retained scenario oracle failed: '+outcome.scenario);
 }
 return {directory,integrityVerified:true,oraclesRechecked:true,passed:result.failed===0&&result.unknown===0,covered:result.executed,planned:result.planned,scope:'retained protocol observations and local hashes; not a signed attestation; fixture journals are not independently reconstructed'};
}
