// Independent JS reconstruction/adversarial checks; no Python result is reused.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {repo,validateNativeWidgetLayer,nativeWidgetPrevious,nativeCounterPrevious,validateNativeCounterLayer,nativeAckPrevious,validateNativeAckLayer,nativeUniquePrevious,validateNativeUniqueLayer,nativePolicy40533Previous,validateNativePolicy40533Layer} from './local-native-runtime.mjs';
import {validateWrangler4164Layer,wrangler4164Previous,supportedBuildsPrevious,widgetAdmissionPrevious} from './local-native-runtime.mjs';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const path='docs/rendezvous/installation-native-widget-source-delta-v1.json';
const toolchain=validateWrangler4164Layer(await readFile(join(repo,'docs/rendezvous/wrangler-4164-toolchain-source-delta-v1.json')));
async function beforeToolchain(name){
 return wrangler4164Previous(name,await supportedBuildsPrevious(name,await widgetAdmissionPrevious(name,await readFile(join(repo,name)))),toolchain);
}
test('native Widget source delta preserves exact original bytes, checks every actual replacement and rejects delta tampering',async()=>{
 const raw=await readFile(join(repo,path)),d=validateNativeWidgetLayer(raw);
 assert.equal(Object.keys(d.changes).length,5);assert.equal(Object.keys(d.additions).length,15);
 assert.equal(d.legacy_public_activation_allowed,false);assert.equal(d.device_acceptance,false);
 assert.throws(()=>validateNativeWidgetLayer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const actual=await beforeToolchain(name);
  assert.equal(hash(await nativeWidgetPrevious(name,actual)),c.before);
  await assert.rejects(nativeWidgetPrevious(name,Buffer.concat([actual,Buffer.from('\n')])));
 }
 for(const[name,pin]of Object.entries({...d.additions,...d.reference_additions}))assert.equal(hash(await nativeCounterPrevious(name,await beforeToolchain(name))),pin);
 const unaffected=await readFile(join(repo,'src/crypto.ts'));
 assert.equal(await nativeWidgetPrevious('src/crypto.ts',unaffected),unaffected);
});

test('counter integrity successor preserves its exact predecessor and rejects each changed source or proof',async()=>{
 const raw=await readFile(join(repo,'docs/rendezvous/native-widget-counter-integrity-source-delta-v1.json')),d=validateNativeCounterLayer(raw);
 assert.equal(Object.keys(d.changes).length,2);assert.throws(()=>validateNativeCounterLayer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const current=await beforeToolchain(name);assert.equal(hash(await nativeCounterPrevious(name,current)),c.before);
  await assert.rejects(nativeCounterPrevious(name,Buffer.concat([current,Buffer.from('\n')])));
 }
});

test('original ACK key-bound successor rejects changed receipt sources, contract reference or delta',async()=>{
 const raw=await readFile(join(repo,'docs/rendezvous/native-ack-key-bounds-source-delta-v1.json')),d=validateNativeAckLayer(raw);
 assert.equal(Object.keys(d.changes).length,2);assert.throws(()=>validateNativeAckLayer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const current=await beforeToolchain(name);assert.equal(hash(await nativeAckPrevious(name,current)),c.before);
  await assert.rejects(nativeAckPrevious(name,Buffer.concat([current,Buffer.from('\n')])));
 }
});

test('unique Apple identity successor rejects changed writer, schema, contract and delta',async()=>{
 const raw=await readFile(join(repo,'docs/rendezvous/native-apple-identity-uniqueness-source-delta-v1.json')),d=validateNativeUniqueLayer(raw);
 assert.equal(Object.keys(d.changes).length,1);assert.equal(Object.keys(d.additions).length,1);
 assert.throws(()=>validateNativeUniqueLayer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const current=await beforeToolchain(name);assert.equal(hash(await nativeUniquePrevious(name,current)),c.before);
  await assert.rejects(nativeUniquePrevious(name,Buffer.concat([current,Buffer.from('\n')])));
 }
 for(const[name,pin]of Object.entries(d.additions))assert.equal(hash(await readFile(join(repo,name))),pin);
});

test('selected signed 40533 policy successor preserves history and rejects each changed input or delta',async()=>{
 const raw=await readFile(join(repo,'docs/rendezvous/native-ios40533-policy-source-delta-v1.json')),d=validateNativePolicy40533Layer(raw);
 assert.equal(Object.keys(d.changes).length,3);assert.equal(Object.keys(d.reference_additions).length,1);
 assert.throws(()=>validateNativePolicy40533Layer(Buffer.concat([raw,Buffer.from('\n')])));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const current=await beforeToolchain(name);assert.equal(hash(await nativePolicy40533Previous(name,current)),c.before);
  await assert.rejects(nativePolicy40533Previous(name,Buffer.concat([current,Buffer.from('\n')])));
 }
 for(const[name,pin]of Object.entries(d.reference_additions))assert.equal(hash(await readFile(join(repo,name))),pin);
});
