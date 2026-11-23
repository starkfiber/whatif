import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {planHarness,runHarness,verifyHarness,harnessScenarios} from '../src/harness.mjs';
const python=execFileSync('/usr/bin/python3',['-c','import os,sys;print(os.path.realpath(sys.executable))'],{encoding:'utf8'}).trim();
async function fixture(t,code='print("{}")'){
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'whatif-harness-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const source=path.join(root,'source');await fs.mkdir(path.join(source,'bastion'),{recursive:true});
 await fs.writeFile(path.join(source,'bastion/__init__.py'),'');await fs.writeFile(path.join(source,'bastion/__main__.py'),code);
 return {root,source,out:path.join(root,'case')};
}
test('harness plan pins source and interpreter without executing; exclusive directories',async t=>{
 const f=await fixture(t,'raise RuntimeError("must not run while planning")');const p=await planHarness({...f,python});
 assert.equal(p.execution,'not-started');assert.equal(p.scenarios,harnessScenarios.length);await assert.rejects(fs.stat(path.join(f.out,'run-start.json')),{code:'ENOENT'});
 await assert.rejects(planHarness({...f,python}),{code:'EEXIST'});
});
test('harness acknowledgement, digest and changed source are refused before execution',async t=>{
 const f=await fixture(t);const p=await planHarness({...f,python});
 await assert.rejects(runHarness(f.out,{ackSource:'wrong',digest:p.digest}),/acknowledgement/);
 await assert.rejects(runHarness(f.out,{ackSource:f.source,digest:'0'.repeat(64)}),/digest/);
 await fs.appendFile(path.join(f.source,'bastion/__main__.py'),'\n# changed');
 await assert.rejects(runHarness(f.out,{ackSource:f.source,digest:p.digest}),/pins changed/);
 await assert.rejects(fs.stat(path.join(f.out,'run-start.json')),{code:'ENOENT'});
});
test('malformed CLI output is failed evidence, never success; used case cannot restart',async t=>{
 const f=await fixture(t,'print("not-json")');const p=await planHarness({...f,python});
 const r=await runHarness(f.out,{ackSource:f.source,digest:p.digest});assert.equal(r.failed,1);assert.equal(r.unknown,6);
 const v=await verifyHarness(f.out);assert(v.integrityVerified);assert(!v.passed);
 await assert.rejects(runHarness(f.out,{ackSource:f.source,digest:p.digest}),{code:'EEXIST'});
 await fs.appendFile(path.join(f.out,'results.json'),' ');await assert.rejects(verifyHarness(f.out),/hash mismatch/);
});
test('harness rejects mutated oracles and output overflow remains bounded verifiable failure',async t=>{
 const f=await fixture(t,'print("x"*100000)');await planHarness({...f,python});
 const file=path.join(f.out,'plan.json'),plan=JSON.parse(await fs.readFile(file));
 plan.scenarios=['claim-success'];await fs.writeFile(file,JSON.stringify(plan));
 await assert.rejects(runHarness(f.out,{ackSource:f.source,digest:'x'}),/oracles/);
 plan.scenarios=harnessScenarios;plan.budgets.maxOutputBytes=1024;await fs.writeFile(file,JSON.stringify(plan,null,2)+'\n');
 const {createHash}=await import('node:crypto');const digest=createHash('sha256').update(await fs.readFile(file)).digest('hex');
 const r=await runHarness(f.out,{ackSource:f.source,digest});assert(r.outputBytes<=1024);assert.equal(r.failed,1);assert.match(r.outcomes[0].error,/output budget/);assert.equal((await verifyHarness(f.out)).passed,false);
});
test('real Bastion campaign covers all fixed local CLI invariants',{skip:!process.env.WHATIF_BASTION_SOURCE},async t=>{
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'whatif-real-harness-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const source=await fs.realpath(process.env.WHATIF_BASTION_SOURCE),out=path.join(root,'case');const p=await planHarness({source,python,out});
 const r=await runHarness(out,{ackSource:source,digest:p.digest});assert.equal(r.failed,0,JSON.stringify(r.outcomes));assert.equal(r.passed,7);assert.equal(r.unknown,0);
 assert.equal((await verifyHarness(out)).passed,true);
});
test('fresh verification rechecks observed assertions even when summary and hashes are rewritten',{skip:!process.env.WHATIF_BASTION_SOURCE},async t=>{
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'whatif-oracle-check-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const source=await fs.realpath(process.env.WHATIF_BASTION_SOURCE),out=path.join(root,'case');const p=await planHarness({source,python,out});await runHarness(out,{ackSource:source,digest:p.digest});
 const {createHash}=await import('node:crypto'),hash=s=>createHash('sha256').update(s).digest('hex');
 const evidence=JSON.parse(await fs.readFile(path.join(out,'command-evidence.json'))),results=JSON.parse(await fs.readFile(path.join(out,'results.json')));
 const changed=JSON.parse(evidence[2].stdout);changed.receipt.outputs.sum=999;evidence[2].stdout=JSON.stringify(changed);results.trace[2].stdoutSha256=hash(evidence[2].stdout);
 for(const [name,value]of [['command-evidence.json',evidence],['results.json',results]])await fs.writeFile(path.join(out,name),JSON.stringify(value,null,2)+'\n');
 const index=JSON.parse(await fs.readFile(path.join(out,'evidence-index.json')));
 for(const name of Object.keys(index.files))index.files[name]=hash(await fs.readFile(path.join(out,name)));
 await fs.writeFile(path.join(out,'evidence-index.json'),JSON.stringify(index,null,2)+'\n');
 await assert.rejects(verifyHarness(out),/Retained scenario oracle failed/);
});
