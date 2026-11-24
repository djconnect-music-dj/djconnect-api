// Independent JS reconstruction/adversarial checks; no Python result is reused.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {repo,validateNativeWidgetLayer,nativeWidgetPrevious,nativeCounterPrevious,validateNativeCounterLayer} from './local-native-runtime.mjs';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const path='docs/rendezvous/installation-native-widget-source-delta-v1.json';
test('native Widget source delta preserves exact original bytes, checks every actual replacement and rejects delta tampering',async()=>{
 const raw=await readFile(join(repo,path)),d=validateNativeWidgetLayer(raw);
 assert.equal(Object.keys(d.changes).length,5);assert.equal(Object.keys(d.additions).length,15);
 assert.equal(d.legacy_public_activation_allowed,false);assert.equal(d.device_acceptance,false);
 assert.throws(()=>validateNativeWidgetLayer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const actual=await readFile(join(repo,name));
  assert.equal(hash(await nativeWidgetPrevious(name,actual)),c.before);
  await assert.rejects(nativeWidgetPrevious(name,Buffer.concat([actual,Buffer.from('\n')])));
 }
 for(const[name,pin]of Object.entries({...d.additions,...d.reference_additions}))assert.equal(hash(await nativeCounterPrevious(name,await readFile(join(repo,name)))),pin);
 const unaffected=await readFile(join(repo,'src/crypto.ts'));
 assert.equal(await nativeWidgetPrevious('src/crypto.ts',unaffected),unaffected);
});

test('counter integrity successor preserves its exact predecessor and rejects each changed source or proof',async()=>{
 const raw=await readFile(join(repo,'docs/rendezvous/native-widget-counter-integrity-source-delta-v1.json')),d=validateNativeCounterLayer(raw);
 assert.equal(Object.keys(d.changes).length,2);assert.throws(()=>validateNativeCounterLayer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const current=await readFile(join(repo,name));assert.equal(hash(await nativeCounterPrevious(name,current)),c.before);
  await assert.rejects(nativeCounterPrevious(name,Buffer.concat([current,Buffer.from('\n')])));
 }
});
