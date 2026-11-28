// API-owned local server experiment. No product endpoint, native target or activation.
import {createHash,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,writeFile,chmod,rm} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {need,ROUTES} from './local-native-files.mjs';
import {statusOnlyOutbound,allowedStatusRequest} from './local-native-egress.mjs';
import {stage40381,check40381Graph,registrationRecoverController} from './private-profile-40381.mjs';

export const repo=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const sha=v=>createHash('sha256').update(v).digest('hex');
const toolFiles=['qualification/rendezvous/local-native-files.mjs','qualification/rendezvous/local-native-egress.mjs','qualification/rendezvous/local-native-runtime.mjs','qualification/rendezvous/run-local-native.mjs','qualification/rendezvous/private-profile-40381.mjs','qualification/rendezvous/run-local-native-40381.mjs'];
export function gitRead(args){
 const env=Object.fromEntries(Object.entries(process.env).filter(([name])=>!name.startsWith('GIT_')));
 Object.assign(env,{GIT_NO_LAZY_FETCH:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0',GIT_NO_REPLACE_OBJECTS:'1'});
 return spawnSync('git',args,{cwd:repo,env,encoding:'utf8',timeout:10000});
}
export async function checkSourcePins(pins,base){
 for(const [p,h] of Object.entries(pins)){need(!p.includes('..')&&!p.startsWith('/'));need(sha(await readFile(join(base,p)))===h);}
}
const nativeDeltaPath='docs/rendezvous/installation-native-widget-source-delta-v1.json';
const nativeDeltaPin='6b3ffda494c1eb530919793555861437bb9d0030330f932803f31349eab79c42';
const nativeChanges=["coordinator/host-app-wake-receiving/native-assertion.ts", "src/index.ts", "src/surface-push/composition.ts", "src/surface-push/handler.ts", "src/surface-push/store.ts"],nativeAdditions=["coordinator/host-app-wake-receiving/native-assertion-crypto.ts", "migrations/0014_native_installation_publisher.sql", "migrations/0015_native_installation_surface_roles.sql", "migrations/0016_native_installation_apple_key.sql", "migrations/0017_native_installation_role_challenges.sql", "src/native-push/first-key-apple.ts", "src/native-push/first-key-service.ts", "src/native-push/first-key-wire.ts", "src/native-push/installation-dispatch.ts", "src/native-push/installation-first-key.ts", "src/native-push/installation-policy.ts", "src/native-push/installation-publisher.ts", "src/native-push/installation-reauthorization.ts", "src/native-push/installation-surface-dispatch.ts", "src/native-push/installation-surface-enrol.ts"];
const nativeReferenceChanges=['coordinator/host-app-wake-receiving/runtime/source-inputs.json'];
const nativeReferenceAdditions=['docs/native-push/NATIVE_INSTALLATION_PUBLISHER_V1.md'];
const sameKeys=(value,keys)=>JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const mapHash=value=>sha(Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a<b?-1:a>b?1:0)))));
export function validateNativeWidgetLayer(raw){
 need(sha(raw)===nativeDeltaPin);const d=JSON.parse(raw);
 need(sameKeys(d,['schema_version','scope','base_source','qualified_product_source','baseline_source_map_sha256','effective_source_map_sha256',
  'changes','additions','reference_changes','reference_additions','prior_bytes_b64','map_additions_are_compiled_inputs_not_claimed_git_additions',
  'legacy_public_activation_allowed','device_acceptance','production_effect_authorized'])&&d.schema_version===1&&
  d.scope==='EXACT_INSTALLATION_NATIVE_WIDGET_SOURCE_NOT_DEVICE_ACCEPTANCE'&&d.base_source==='878a6701894d3044c29df3f85fcd3a17a4cffe71'&&
  d.qualified_product_source==='0434553364bad3916ab21372cc7bef57f34f0e04'&&d.map_additions_are_compiled_inputs_not_claimed_git_additions===true&&
  d.legacy_public_activation_allowed===false&&d.device_acceptance===false&&d.production_effect_authorized===false&&
  sameKeys(d.changes,nativeChanges)&&sameKeys(d.additions,nativeAdditions)&&sameKeys(d.reference_changes,nativeReferenceChanges)&&
  sameKeys(d.reference_additions,nativeReferenceAdditions)&&sameKeys(d.prior_bytes_b64,[...nativeChanges,...nativeReferenceChanges]));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const old=Buffer.from(d.prior_bytes_b64[name],'base64');need(sameKeys(c,['before','after'])&&c.before!==c.after&&
   old.toString('base64')===d.prior_bytes_b64[name]&&sha(old)===c.before);
 }
 return d;
}
async function nativeLayer(){return validateNativeWidgetLayer(await readFile(join(repo,nativeDeltaPath)));}
const counterDeltaPath='docs/rendezvous/native-widget-counter-integrity-source-delta-v1.json';
const counterDeltaPin='b05b708ea760dedf25c56ed008f2e7d9ac6d7844b7924d3ce902266b30234fb2';
const counterChanges=['coordinator/host-app-wake-receiving/native-assertion-crypto.ts','src/native-push/installation-reauthorization.ts'];
export function validateNativeCounterLayer(raw){
 need(sha(raw)===counterDeltaPin);const d=JSON.parse(raw);
 need(sameKeys(d,['schema_version','scope','base_source','qualified_product_source','baseline_source_map_sha256','effective_source_map_sha256',
  'changes','reference_changes','prior_bytes_b64','legacy_public_activation_allowed','device_acceptance','production_effect_authorized'])&&
  d.schema_version===1&&d.scope==='EXACT_NATIVE_WIDGET_COUNTER_INTEGRITY_NOT_AUTHORITY'&&
  d.base_source==='a926c936881bdbf80d12f464ab3eef9aadcfac56'&&d.qualified_product_source==='d9df1610584960a7843361e9f8e5533b07bf85be'&&
  d.legacy_public_activation_allowed===false&&d.device_acceptance===false&&d.production_effect_authorized===false&&
  sameKeys(d.changes,counterChanges)&&sameKeys(d.reference_changes,nativeReferenceChanges)&&sameKeys(d.prior_bytes_b64,[...counterChanges,...nativeReferenceChanges]));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const old=Buffer.from(d.prior_bytes_b64[name],'base64');need(sameKeys(c,['before','after'])&&c.before!==c.after&&
   old.toString('base64')===d.prior_bytes_b64[name]&&sha(old)===c.before);
 }
 return d;
}
async function counterLayer(){return validateNativeCounterLayer(await readFile(join(repo,counterDeltaPath)));}
const ackDeltaPath='docs/rendezvous/native-ack-key-bounds-source-delta-v1.json';
const ackDeltaPin='68ced5635e8010c94203c09711b3ab16f6cac15e6dea4c6ed07518f17a669ea5';
const ackChanges=['src/native-push/first-key-apple.ts','src/native-push/first-key-service.ts'];
export function validateNativeAckLayer(raw){
 need(sha(raw)===ackDeltaPin);const d=JSON.parse(raw);
 need(sameKeys(d,['schema_version','scope','base_source','qualified_product_source','baseline_source_map_sha256','effective_source_map_sha256',
  'changes','reference_changes','prior_bytes_b64','legacy_public_activation_allowed','device_acceptance','production_effect_authorized'])&&
  d.schema_version===1&&d.scope==='EXACT_PRODUCTION_NATIVE_ACK_KEY_BOUNDS_NOT_AUTHORITY'&&
  d.base_source==='dc82bbea402114a7e3b6bbea148b4fc90b0a9a6b'&&d.qualified_product_source==='3c2151e3b0e0dd29f33178b0061b576b8da9fd89'&&
  d.legacy_public_activation_allowed===false&&d.device_acceptance===false&&d.production_effect_authorized===false&&
  sameKeys(d.changes,ackChanges)&&sameKeys(d.reference_changes,nativeReferenceAdditions)&&sameKeys(d.prior_bytes_b64,[...ackChanges,...nativeReferenceAdditions]));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const old=Buffer.from(d.prior_bytes_b64[name],'base64');need(sameKeys(c,['before','after'])&&c.before!==c.after&&
   old.toString('base64')===d.prior_bytes_b64[name]&&sha(old)===c.before);
 }
 return d;
}
async function ackLayer(){return validateNativeAckLayer(await readFile(join(repo,ackDeltaPath)));}
const uniqueDeltaPath='docs/rendezvous/native-apple-identity-uniqueness-source-delta-v1.json';
const uniqueDeltaPin='4df2a69f62d2ee0d69ad318bbefc4117b965c8c10ef2c5aca21e9ae3449a08c6';
const uniqueChanges=['src/native-push/first-key-service.ts'],uniqueAdditions=['migrations/0018_native_installation_unique_apple_identity.sql'];
export function validateNativeUniqueLayer(raw){
 need(sha(raw)===uniqueDeltaPin);const d=JSON.parse(raw);
 need(sameKeys(d,['schema_version','scope','base_source','qualified_product_source','baseline_source_map_sha256','effective_source_map_sha256',
  'changes','additions','reference_changes','prior_bytes_b64','legacy_public_activation_allowed','device_acceptance','production_effect_authorized'])&&
  d.schema_version===1&&d.scope==='EXACT_REGISTERED_APPLE_KEY_UNIQUENESS_NOT_AUTHORITY'&&
  d.base_source==='0e70921a4d96f24466c8eeabf22af05d2e4e5b10'&&d.qualified_product_source==='6d28012f2dc67bf46f327ff0a699f1dcce38d3d6'&&
  d.legacy_public_activation_allowed===false&&d.device_acceptance===false&&d.production_effect_authorized===false&&
  sameKeys(d.changes,uniqueChanges)&&sameKeys(d.additions,uniqueAdditions)&&sameKeys(d.reference_changes,nativeReferenceAdditions)&&sameKeys(d.prior_bytes_b64,[...uniqueChanges,...nativeReferenceAdditions]));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const old=Buffer.from(d.prior_bytes_b64[name],'base64');need(sameKeys(c,['before','after'])&&c.before!==c.after&&
   old.toString('base64')===d.prior_bytes_b64[name]&&sha(old)===c.before);
 }
 return d;
}
async function uniqueLayer(){return validateNativeUniqueLayer(await readFile(join(repo,uniqueDeltaPath)));}
const policy40533DeltaPath='docs/rendezvous/native-ios40533-policy-source-delta-v1.json';
const policy40533DeltaPin='75b7035dd6288326ae5518eff579cc921fb56eb6ff5484a75bc124c575b3bbfa';
const policy40533Changes=['src/native-push/installation-policy.ts','src/native-push/installation-first-key.ts','src/native-push/first-key-service.ts'];
const policy40533References=['docs/native-push/signed-ios-40533-policy-evidence.json'];
export function validateNativePolicy40533Layer(raw){
 need(sha(raw)===policy40533DeltaPin);const d=JSON.parse(raw);
 need(sameKeys(d,['schema_version','scope','base_source','qualified_product_source','baseline_source_map_sha256','effective_source_map_sha256',
  'changes','reference_changes','reference_additions','prior_bytes_b64','legacy_public_activation_allowed','device_acceptance','production_effect_authorized'])&&
  d.schema_version===1&&d.scope==='EXACT_SELECTED_SIGNED_IOS40533_POLICY_NOT_NATIVE_ACCEPTANCE'&&
  d.base_source==='c9da97d27123afa2d04098d19e3f30e1afc37d30'&&d.qualified_product_source==='9938907422fdf3f9c25d750b706c9eada9f2d360'&&
  d.legacy_public_activation_allowed===false&&d.device_acceptance===false&&d.production_effect_authorized===false&&
  sameKeys(d.changes,policy40533Changes)&&sameKeys(d.reference_changes,nativeReferenceAdditions)&&sameKeys(d.reference_additions,policy40533References)&&
  sameKeys(d.prior_bytes_b64,[...policy40533Changes,...nativeReferenceAdditions]));
 for(const[name,c]of Object.entries({...d.changes,...d.reference_changes})){
  const old=Buffer.from(d.prior_bytes_b64[name],'base64');need(sameKeys(c,['before','after'])&&c.before!==c.after&&
   old.toString('base64')===d.prior_bytes_b64[name]&&sha(old)===c.before);
 }
 return d;
}
async function policy40533Layer(){return validateNativePolicy40533Layer(await readFile(join(repo,policy40533DeltaPath)));}
export async function nativePolicy40533Previous(name,raw){
 if(![...policy40533Changes,...nativeReferenceAdditions].includes(name))return raw;
 const d=await policy40533Layer(),c=d.changes[name]||d.reference_changes[name];need(sha(raw)===c.after);
 return Buffer.from(d.prior_bytes_b64[name],'base64');
}
export async function nativeUniquePrevious(name,raw){
 raw=await nativePolicy40533Previous(name,raw);
 if(![...uniqueChanges,...nativeReferenceAdditions].includes(name))return raw;
 const d=await uniqueLayer(),c=d.changes[name]||d.reference_changes[name];need(sha(raw)===c.after);
 return Buffer.from(d.prior_bytes_b64[name],'base64');
}
export async function nativeAckPrevious(name,raw){
 raw=await nativeUniquePrevious(name,raw);
 if(![...ackChanges,...nativeReferenceAdditions].includes(name))return raw;
 const d=await ackLayer(),c=d.changes[name]||d.reference_changes[name];need(sha(raw)===c.after);
 return Buffer.from(d.prior_bytes_b64[name],'base64');
}
export async function nativeCounterPrevious(name,raw){
 raw=await nativeAckPrevious(name,raw);
 if(![...counterChanges,...nativeReferenceChanges].includes(name))return raw;
 const d=await counterLayer(),c=d.changes[name]||d.reference_changes[name];need(sha(raw)===c.after);
 return Buffer.from(d.prior_bytes_b64[name],'base64');
}
export async function nativeWidgetPrevious(name,raw){
 raw=await nativeCounterPrevious(name,raw);
 if(![...nativeChanges,...nativeReferenceChanges].includes(name))return raw;
 const d=await nativeLayer(),c=d.changes[name]||d.reference_changes[name];need(sha(raw)===c.after);
 return Buffer.from(d.prior_bytes_b64[name],'base64');
}
const wrangler4164Path='docs/rendezvous/wrangler-4164-toolchain-source-delta-v1.json';
const wrangler4164Pin='097e0869b700c8ee85967bbbe452c305bb0e036755b8430f1afae38d4ea66ef8';
const wrangler4164Provenance='qualification/rendezvous/compatible-runtime-dependency-provenance-v8.json';

export function validateWrangler4164Layer(raw){
 need(sha(raw)===wrangler4164Pin);
 const delta=JSON.parse(raw);
 need(delta.schema_version===1&&delta.scope==='EXACT_WRANGLER_4164_TOOLCHAIN_REFRESH_NOT_ACTIVATION'&&
  delta.public_activation_allowed===false&&delta.base_source==='4ace9ae7d9224411212ae1138b96fd75914cadde'&&
  sameKeys(delta.reference_additions,[wrangler4164Provenance]));
 return delta;
}

export function wrangler4164Previous(name,raw,delta){
 const change=delta.changes[name]||delta.reference_changes[name];
 if(!change)return raw;
 need(sameKeys(change,['before','after','revert'])&&sha(raw)===change.after&&change.before!==change.after&&
  Array.isArray(change.revert)&&change.revert.length>0);
 let previousOffset=raw.length+1;
 for(const edit of change.revert.toReversed()){
  const {offset,remove,restore}=edit;
  need(sameKeys(edit,['offset','remove','restore'])&&Number.isSafeInteger(offset)&&Number.isSafeInteger(remove)&&
   typeof restore==='string'&&offset>=0&&offset<previousOffset&&remove>=0&&offset+remove<=Math.min(previousOffset,raw.length));
  raw=Buffer.concat([raw.subarray(0,offset),Buffer.from(restore),raw.subarray(offset+remove)]);
  previousOffset=offset;
 }
 need(sha(raw)===change.before);
 return raw;
}

const supportedBuildsPath = 'docs/rendezvous/native-ios-supported-builds-source-delta-v1.json';
const supportedBuildsPin = '339f2a15b852309d6ca9d255f911908f79662e17584dbcc6ffd4afa3ea4ff4dc';

async function supportedBuildsLayer() {
 const raw = await readFile(join(repo, supportedBuildsPath));
 need(sha(raw) === supportedBuildsPin);
 const delta = JSON.parse(raw);
 need(delta.schema_version === 1 && delta.scope === 'IOS_SUPPORTED_BUILDS_SOURCE_ONLY' &&
      delta.production_effect_authorized === false);
 return delta;
}

const applePushRoutingPath = 'docs/rendezvous/apple-push-routing-source-delta-v1.json';
const applePushRoutingPin = '6a503fe0936a659429ba77944bf24aef939ba267a1048421af50ef3ded700c77';
async function applePushRoutingLayer() {
 const raw = await readFile(join(repo,applePushRoutingPath));
 need(sha(raw) === applePushRoutingPin);
 const delta = JSON.parse(raw);
 need(delta.schema_version === 1 && delta.scope === 'APPLE_PUSH_ROUTING_SOURCE_ONLY' &&
      delta.production_effect_authorized === false);
 return delta;
}

async function applePushRoutingPrevious(name, raw) {
 const change = (await applePushRoutingLayer()).changes[name];
 if (!change) return raw;
 const previous = Buffer.from(change.previous_bytes_b64,'base64');
 need(sha(raw) === change.after && sha(previous) === change.before);
 return previous;
}

export async function supportedBuildsPrevious(name, raw) {
 raw = await applePushRoutingPrevious(name, raw);
 const delta = await supportedBuildsLayer();
 const change = delta.changes[name] ?? delta.reference_changes[name];
 if (!change) return raw;
 const previous = Buffer.from(change.previous_bytes_b64, 'base64');
 need(sha(raw) === change.after && sha(previous) === change.before);
 return previous;
}

const widgetAdmissionPath = "docs/rendezvous/native-widget-continuous-admission-source-delta-v1.json";
const widgetAdmissionPin = "db0b03fa5ddb43d796cae00672683d8e48430acd250b27fbf96e23132f4b2c54";
async function widgetAdmissionLayer() {
 const raw=await readFile(join(repo,widgetAdmissionPath));
 need(sha(raw)===widgetAdmissionPin);
 const layer=JSON.parse(raw);
 need(layer.schema_version===1 && layer.scope==="NATIVE_WIDGET_CONTINUOUS_ADMISSION_SOURCE_ONLY" &&
      layer.base_source==="a2683b003a0617bea9bd11091dc04afc6439344c" && layer.production_effect_authorized===false);
 return layer;
}

export async function widgetAdmissionPrevious(name,raw) {
 const layer=await widgetAdmissionLayer();
 const change=layer.changes[name] ?? layer.reference_changes[name];
 if (!change) return raw;
 const previous=Buffer.from(change.previous_bytes_b64,"base64");
 need(sha(raw)===change.after && sha(previous)===change.before && change.before!==change.after);
 return previous;
}

async function historicalRead(path,delta,encoding){
 const name=resolve(path).slice(repo.length+1);
 const raw=await nativeWidgetPrevious(name,wrangler4164Previous(name,await supportedBuildsPrevious(name,await widgetAdmissionPrevious(name,await readFile(path))),delta));
 return encoding?raw.toString(encoding):raw;
}
export async function sourceSnapshot(){
 const status=gitRead(['status','--porcelain','--untracked-files=normal']);need(status.status===0&&status.stdout==='');
 const checked=spawnSync('python3',['scripts/validate_rendezvous_deployment_plan.py'],{cwd:repo,encoding:'utf8',timeout:30000});
 need(checked.status===0);const preparation=JSON.parse(checked.stdout);need(preparation.activation_allowed===false);
 const publishedPlan=JSON.parse(await readFile(join(repo,'docs/rendezvous/deployment-preparation-v1.json'))),native=await nativeLayer(),counter=await counterLayer(),ack=await ackLayer(),unique=await uniqueLayer(),policy40533=await policy40533Layer();
 const wrangler4164Raw=await readFile(join(repo,wrangler4164Path));
 const wrangler4164=validateWrangler4164Layer(wrangler4164Raw);
 need(publishedPlan.reference_hashes[wrangler4164Path]===wrangler4164Pin&&
  publishedPlan.reference_hashes[wrangler4164Provenance]===wrangler4164.reference_additions[wrangler4164Provenance]);
 const plan={...publishedPlan,source_hashes:{...publishedPlan.source_hashes},reference_hashes:{...publishedPlan.reference_hashes}};
 const widget=await widgetAdmissionLayer();
 need(plan.reference_hashes[widgetAdmissionPath]===widgetAdmissionPin &&
      plan.source_provenance.native_widget_continuous_admission_delta_sha256===widgetAdmissionPin &&
      plan.source_provenance.native_widget_continuous_admission_source_map_sha256===widget.effective_source_map_sha256 &&
      mapHash(plan.source_hashes)===widget.effective_source_map_sha256);
 for (const [hashes,changes] of [[plan.source_hashes,widget.changes],[plan.reference_hashes,widget.reference_changes]]) {
  for (const [name,change] of Object.entries(changes)) {
   need(hashes[name]===change.after);
   await widgetAdmissionPrevious(name,await readFile(join(repo,name)));
   hashes[name]=change.before;
  }
 }
 delete plan.reference_hashes[widgetAdmissionPath];
 need(mapHash(plan.source_hashes)===widget.baseline_source_map_sha256);
 const push = await applePushRoutingLayer();
 need(plan.reference_hashes[applePushRoutingPath] === applePushRoutingPin &&
      publishedPlan.source_provenance.apple_push_routing_delta_sha256 === applePushRoutingPin &&
      publishedPlan.source_provenance.apple_push_routing_source_map_sha256 === push.effective_source_map_sha256 &&
      mapHash(plan.source_hashes) === push.effective_source_map_sha256);
 for (const [name,change] of Object.entries(push.changes)) {
  need(plan.source_hashes[name] === change.after);
  await applePushRoutingPrevious(name,await readFile(join(repo,name)));
  plan.source_hashes[name] = change.before;
 }
 for (const [name,pin] of Object.entries(push.reference_additions)) {
  need(plan.reference_hashes[name] === pin && sha(await readFile(join(repo,name))) === pin);
  delete plan.reference_hashes[name];
 }
 delete plan.reference_hashes[applePushRoutingPath];
 need(mapHash(plan.source_hashes) === push.baseline_source_map_sha256);
 const supported = await supportedBuildsLayer();
 need(publishedPlan.reference_hashes[supportedBuildsPath] === supportedBuildsPin &&
      publishedPlan.source_provenance.native_ios_supported_builds_delta_sha256 === supportedBuildsPin &&
      publishedPlan.source_provenance.native_ios_supported_builds_source_map_sha256 === supported.effective_source_map_sha256 &&
      supported.effective_source_map_sha256 === mapHash(plan.source_hashes));
 for (const [hashes, changes] of [[plan.source_hashes, supported.changes], [plan.reference_hashes, supported.reference_changes]]) {
  for (const [name, change] of Object.entries(changes)) {
   need(hashes[name] === change.after);
   await supportedBuildsPrevious(name, await widgetAdmissionPrevious(name, await readFile(join(repo, name))));
   hashes[name] = change.before;
  }
 }
 delete plan.reference_hashes[supportedBuildsPath];
 const wrangler4164SourceMap = mapHash(plan.source_hashes);
 need(wrangler4164SourceMap === supported.baseline_source_map_sha256);
 for(const [hashes,changes] of [[plan.source_hashes,wrangler4164.changes],[plan.reference_hashes,wrangler4164.reference_changes]]){
  for(const [name,change] of Object.entries(changes)){
   need(hashes[name]===change.after);
   await historicalRead(join(repo,name),wrangler4164);
   hashes[name]=change.before;
  }
 }
 delete plan.reference_hashes[wrangler4164Path];
 delete plan.reference_hashes[wrangler4164Provenance];
 delete plan.reference_hashes['qualification/rendezvous/compatible-runtime-dependency-provenance-v7.json'];
 const wrangler4164PreviousSources={...plan.source_hashes};
 need(mapHash(wrangler4164PreviousSources)===wrangler4164.baseline_source_map_sha256&&
  wrangler4164SourceMap===wrangler4164.effective_source_map_sha256&&
  publishedPlan.source_provenance.wrangler_4164_delta_sha256===wrangler4164Pin&&
  publishedPlan.source_provenance.wrangler_4164_source_map_sha256===wrangler4164.effective_source_map_sha256);
 for(const[name,c]of Object.entries(policy40533.changes)){need(plan.source_hashes[name]===c.after);plan.source_hashes[name]=c.before;}
 for(const[name,c]of Object.entries(policy40533.reference_changes)){need(plan.reference_hashes[name]===c.after);plan.reference_hashes[name]=c.before;}
 for(const[name,pin]of Object.entries(policy40533.reference_additions)){need(plan.reference_hashes[name]===pin);delete plan.reference_hashes[name];}
 const uniquePublishedSources={...plan.source_hashes};
 for(const[name,c]of Object.entries(unique.changes)){need(plan.source_hashes[name]===c.after);plan.source_hashes[name]=c.before;}
 for(const[name,pin]of Object.entries(unique.additions)){need(plan.source_hashes[name]===pin);delete plan.source_hashes[name];}
 for(const[name,c]of Object.entries(unique.reference_changes)){need(plan.reference_hashes[name]===c.after);plan.reference_hashes[name]=c.before;}
 const ackPublishedSources={...plan.source_hashes};
 for(const[name,c]of Object.entries(ack.changes)){need(plan.source_hashes[name]===c.after);plan.source_hashes[name]=c.before;}
 for(const[name,c]of Object.entries(ack.reference_changes)){need(plan.reference_hashes[name]===c.after);plan.reference_hashes[name]=c.before;}
 const counterPublishedSources={...plan.source_hashes};
 for(const[name,c]of Object.entries(counter.changes)){need(plan.source_hashes[name]===c.after);plan.source_hashes[name]=c.before;}
 for(const[name,c]of Object.entries(counter.reference_changes)){need(plan.reference_hashes[name]===c.after);plan.reference_hashes[name]=c.before;}
 for(const[name,c]of Object.entries(native.reference_changes)){need(plan.reference_hashes[name]===c.after);plan.reference_hashes[name]=c.before;}

 const rootPath='docs/rendezvous/closed-enrollment-service-product-observations-v2.json';
 const rootRaw=await readFile(join(repo,rootPath));
 need(plan.reference_hashes[rootPath]===sha(rootRaw));
 const root=JSON.parse(rootRaw);
 // Retain both historical proofs and exact separately validated deltas.
 // No current checkout/JSON may replace an original proof or authorize native.
 const delta=preparation.qualification_workflow_delta;
 need(delta&&Object.keys(delta).join(',')==='.github/workflows/ci-cd.yml');
 const closedPath='docs/rendezvous/host-wake-closed-root-source-delta-v1.json';
 const closedRaw=await readFile(join(repo,closedPath)),provenance=preparation.source_provenance;
 need(plan.reference_hashes[closedPath]===sha(closedRaw)&&sha(closedRaw)===provenance.closed_receiving_root_delta_sha256);
 const closed=JSON.parse(closedRaw);
 need(closed.scope==='EXACT_CLOSED_RECEIVING_ROOT_SOURCE_DELTA_NOT_ACTIVATION'&&closed.public_activation_allowed===false);
 need(closed.baseline_source_map_sha256===provenance.qualified_source_map_sha256&&closed.effective_source_map_sha256===provenance.closed_receiving_root_source_map_sha256);
 const retentionPath='docs/rendezvous/active-ci-retention-source-delta-v1.json',retentionRaw=await readFile(join(repo,retentionPath));
 need(plan.reference_hashes[retentionPath]===sha(retentionRaw)&&sha(retentionRaw)===provenance.active_ci_retention_delta_sha256);
 const retention=JSON.parse(retentionRaw);
 need(retention.scope==='EXACT_ACTIVE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'&&retention.public_activation_allowed===false);
 need(retention.baseline_source_map_sha256===closed.effective_source_map_sha256&&retention.effective_source_map_sha256===provenance.active_ci_retention_source_map_sha256);
 const categoryPath='docs/rendezvous/native-first-category-source-delta-v1.json',categoryRaw=await readFile(join(repo,categoryPath));
 need(plan.reference_hashes[categoryPath]===sha(categoryRaw)&&sha(categoryRaw)===provenance.native_first_category_delta_sha256);
 const category=JSON.parse(categoryRaw);need(category.scope==='EXACT_PRIVATE_FIRST_CATEGORY_SOURCE_NOT_ACTIVATION'&&category.public_activation_allowed===false);
 need(category.baseline_source_map_sha256===retention.effective_source_map_sha256&&category.effective_source_map_sha256===provenance.native_first_category_source_map_sha256);
 const mountPath='docs/rendezvous/private-receiving-mount-source-delta-v1.json',mountRaw=await readFile(join(repo,mountPath));
 need(plan.reference_hashes[mountPath]===sha(mountRaw)&&sha(mountRaw)===provenance.private_receiving_mount_delta_sha256);
 const mount=JSON.parse(mountRaw);need(mount.scope==='EXACT_PRIVATE_RECEIVING_MOUNT_NOT_EFFECT_AUTHORIZATION'&&mount.private_http_mount_selected===true&&mount.production_effect_authorized===false);
 need(mount.baseline_source_map_sha256===category.effective_source_map_sha256&&mount.effective_source_map_sha256===provenance.private_receiving_mount_source_map_sha256);
 const dependencyPath='docs/rendezvous/pkijs-wrangler-dependency-refresh-source-delta-v1.json',dependencyRaw=await readFile(join(repo,dependencyPath));
 need(plan.reference_hashes[dependencyPath]===sha(dependencyRaw)&&sha(dependencyRaw)===provenance.dependency_refresh_delta_sha256);
 const dependency=JSON.parse(dependencyRaw);need(dependency.scope==='EXACT_PKIJS_WRANGLER_DEPENDENCY_REFRESH_NOT_ACTIVATION'&&dependency.public_activation_allowed===false&&dependency.production_effect_authorized===false);
 need(dependency.baseline_source_map_sha256===mount.effective_source_map_sha256&&dependency.effective_source_map_sha256===provenance.dependency_refresh_source_map_sha256);
 const watchPath='docs/rendezvous/watch-topic-source-delta-v1.json',watchRaw=await readFile(join(repo,watchPath));
 need(plan.reference_hashes[watchPath]===sha(watchRaw)&&sha(watchRaw)===provenance.watch_topic_delta_sha256);
 const watch=JSON.parse(watchRaw);need(watch.scope==='EXACT_WATCH_TOPIC_ALIGNMENT_NOT_ACTIVATION'&&watch.public_activation_allowed===false&&watch.production_effect_authorized===false);
 need(watch.baseline_source_map_sha256===dependency.effective_source_map_sha256&&watch.effective_source_map_sha256===provenance.watch_topic_source_map_sha256);
 const receiptPath='docs/rendezvous/watch-registration-receipt-source-delta-v1.json',receiptRaw=await readFile(join(repo,receiptPath));
 need(plan.reference_hashes[receiptPath]===sha(receiptRaw)&&sha(receiptRaw)===provenance.watch_registration_receipt_delta_sha256);
 const receipt=JSON.parse(receiptRaw);need(receipt.scope==='EXACT_WATCH_REGISTRATION_RECEIPT_NOT_ACTIVATION'&&receipt.public_activation_allowed===false&&receipt.production_effect_authorized===false);
 need(receipt.baseline_source_map_sha256===watch.effective_source_map_sha256&&receipt.effective_source_map_sha256===provenance.watch_registration_receipt_source_map_sha256);
 const releaseRetentionPath='docs/rendezvous/release-ci-retention-source-delta-v1.json',releaseRetentionRaw=await readFile(join(repo,releaseRetentionPath));
 need(plan.reference_hashes[releaseRetentionPath]===sha(releaseRetentionRaw)&&sha(releaseRetentionRaw)===provenance.release_ci_retention_delta_sha256);
 const releaseRetention=JSON.parse(releaseRetentionRaw);need(releaseRetention.scope==='EXACT_RELEASE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'&&releaseRetention.public_activation_allowed===false);
 need(releaseRetention.baseline_source_map_sha256===receipt.effective_source_map_sha256&&releaseRetention.effective_source_map_sha256===provenance.release_ci_retention_source_map_sha256);
 const bindingsPath='docs/rendezvous/closed-production-bindings-source-delta-v1.json';
 const bindingsRaw=await readFile(join(repo,bindingsPath));
 need(plan.reference_hashes[bindingsPath]===sha(bindingsRaw)&&sha(bindingsRaw)===provenance.closed_production_bindings_delta_sha256);
 const bindings=JSON.parse(bindingsRaw);
 need(bindings.scope==='EXACT_CLOSED_PRODUCTION_BINDINGS_SOURCE_ONLY'&&bindings.public_activation_allowed===false&&bindings.production_effect_authorized===false);
 need(bindings.baseline_source_map_sha256===releaseRetention.effective_source_map_sha256&&bindings.effective_source_map_sha256===provenance.closed_production_bindings_source_map_sha256);
 const toolchainPath='docs/rendezvous/toolchain-development-dependency-refresh-v1.json';
 const toolchainRaw=await readFile(join(repo,toolchainPath));
 need(plan.reference_hashes[toolchainPath]===sha(toolchainRaw)&&sha(toolchainRaw)===provenance.toolchain_refresh_delta_sha256);
 const toolchain=JSON.parse(toolchainRaw);
 need(toolchain.scope==='EXACT_TOOLCHAIN_AND_DEVELOPMENT_DEPENDENCY_REFRESH_NOT_ACTIVATION'&&toolchain.public_activation_allowed===false);
 need(toolchain.baseline_source_map_sha256===bindings.effective_source_map_sha256&&toolchain.effective_source_map_sha256===provenance.toolchain_refresh_source_map_sha256);
 const toolchainFiles=["package-lock.json","package.json","scripts/qualify_rendezvous_product_build.mjs"];
 need(Object.keys(toolchain.changes).length===toolchainFiles.length&&toolchainFiles.every(name=>Object.hasOwn(toolchain.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const maintenancePath='docs/rendezvous/api-maintenance-source-delta-v1.json';
 const maintenanceRaw=await readFile(join(repo,maintenancePath));
 need(plan.reference_hashes[maintenancePath]===sha(maintenanceRaw)&&sha(maintenanceRaw)===provenance.api_maintenance_delta_sha256);
 const maintenance=JSON.parse(maintenanceRaw);
 need(maintenance.scope==='EXACT_API_MAINTENANCE_SOURCE_ONLY_NOT_ACTIVATION'&&maintenance.public_activation_allowed===false);
 need(maintenance.baseline_source_map_sha256===toolchain.effective_source_map_sha256&&maintenance.effective_source_map_sha256===provenance.api_maintenance_source_map_sha256);
 const maintenanceFiles=["src/auth.ts","src/handlers/install.ts","src/messages.ts","src/repositories/installTokens.ts","src/repositories/registrations.ts"];
 need(Object.keys(maintenance.changes).length===maintenanceFiles.length&&maintenanceFiles.every(name=>Object.hasOwn(maintenance.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const stablePath='docs/rendezvous/stable-api-release-source-delta-v1.json';
 const stableRaw=await readFile(join(repo,stablePath));
 need(plan.reference_hashes[stablePath]===sha(stableRaw)&&sha(stableRaw)===provenance.stable_release_delta_sha256);
 const stable=JSON.parse(stableRaw);
 need(stable.scope==='EXACT_STABLE_API_RELEASE_METADATA_NOT_ACTIVATION'&&stable.public_activation_allowed===false);
 need(stable.baseline_source_map_sha256===maintenance.effective_source_map_sha256&&stable.effective_source_map_sha256===provenance.stable_release_source_map_sha256);
 const stableFiles=["package-lock.json","package.json","scripts/qualify_rendezvous_product_build.mjs","src/releaseMetadata.ts"];
 need(Object.keys(stable.changes).length===stableFiles.length&&stableFiles.every(name=>Object.hasOwn(stable.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const erasurePath='docs/rendezvous/push-erasure-source-delta-v1.json';
 const erasureRaw=await readFile(join(repo,erasurePath));
 need(plan.reference_hashes[erasurePath]===sha(erasureRaw)&&sha(erasureRaw)===provenance.push_erasure_delta_sha256);
 const erasure=JSON.parse(erasureRaw);
 need(erasure.scope==='EXACT_PUSH_ERASURE_SOURCE_NOT_RENDEZVOUS_ACTIVATION'&&erasure.public_activation_allowed===false);
 need(erasure.baseline_source_map_sha256===stable.effective_source_map_sha256&&erasure.effective_source_map_sha256===provenance.push_erasure_source_map_sha256);
 const keyAddressPath='docs/rendezvous/shared-key-address-delta-v1.json';
 const keyAddressRaw=await readFile(join(repo,keyAddressPath));
 need(plan.reference_hashes[keyAddressPath]===sha(keyAddressRaw)&&sha(keyAddressRaw)===provenance.shared_key_address_delta_sha256);
 const keyAddress=JSON.parse(keyAddressRaw);
 need(keyAddress.scope==='EXACT_SHARED_KEY_ADDRESS_DERIVATION_NOT_ACTIVATION'&&keyAddress.public_activation_allowed===false);
 need(keyAddress.baseline_source_map_sha256===erasure.effective_source_map_sha256&&keyAddress.effective_source_map_sha256===provenance.shared_key_address_source_map_sha256);
 const testFlightPath='docs/rendezvous/testflight-release-source-delta-v1.json';
 const testFlightRaw=await readFile(join(repo,testFlightPath));
 need(plan.reference_hashes[testFlightPath]===sha(testFlightRaw)&&sha(testFlightRaw)===provenance.testflight_profile_delta_sha256);
 const testFlight=JSON.parse(testFlightRaw);
 need(testFlight.scope==='EXACT_TESTFLIGHT_RELEASE_PROFILE_NOT_ACTIVATION'&&testFlight.public_activation_allowed===false);
 need(testFlight.baseline_source_map_sha256===keyAddress.effective_source_map_sha256&&testFlight.effective_source_map_sha256===provenance.testflight_profile_source_map_sha256);
 const publicTrialPath='docs/rendezvous/public-testflight-trial-source-delta-v1.json';
 const publicTrialRaw=await readFile(join(repo,publicTrialPath));
 need(plan.reference_hashes[publicTrialPath]===sha(publicTrialRaw)&&sha(publicTrialRaw)===provenance.public_trial_delta_sha256);
 const publicTrial=JSON.parse(publicTrialRaw);
 need(publicTrial.scope==='PUBLIC_TESTFLIGHT_TRIAL_CONFIGURED_NOT_DEPLOYED');
 need(publicTrial.baseline_source_map_sha256===testFlight.effective_source_map_sha256&&publicTrial.effective_source_map_sha256===provenance.public_trial_source_map_sha256);
 const alwaysOnPath='docs/rendezvous/always-on-testflight-source-delta-v1.json';
 const alwaysOnRaw=await readFile(join(repo,alwaysOnPath));
 need(plan.reference_hashes[alwaysOnPath]===sha(alwaysOnRaw)&&sha(alwaysOnRaw)===provenance.always_on_testflight_delta_sha256);
 const alwaysOn=JSON.parse(alwaysOnRaw);
 need(alwaysOn.scope==='PUBLIC_TESTFLIGHT_ALWAYS_ON_SOURCE_NOT_DEPLOYED');
 need(alwaysOn.baseline_source_map_sha256===publicTrial.effective_source_map_sha256&&alwaysOn.effective_source_map_sha256===provenance.always_on_testflight_source_map_sha256);
 const wranglerPath='docs/rendezvous/wrangler-4160-toolchain-source-delta-v1.json';
 const wranglerRaw=await readFile(join(repo,wranglerPath));
 need(plan.reference_hashes[wranglerPath]===sha(wranglerRaw)&&sha(wranglerRaw)===provenance.wrangler_4160_delta_sha256);
 const wrangler=JSON.parse(wranglerRaw);
 need(wrangler.scope==='EXACT_WRANGLER_4160_TOOLCHAIN_REFRESH_NOT_ACTIVATION'&&wrangler.public_activation_allowed===false);
 need(wrangler.baseline_source_map_sha256===alwaysOn.effective_source_map_sha256&&wrangler.effective_source_map_sha256===provenance.wrangler_4160_source_map_sha256);
 const governancePath='docs/rendezvous/org-governance-source-delta-v1.json';
 const governanceRaw=await readFile(join(repo,governancePath));
 need(plan.reference_hashes[governancePath]===sha(governanceRaw)&&sha(governanceRaw)===provenance.org_governance_delta_sha256);
 const governance=JSON.parse(governanceRaw);
 need(governance.scope==='EXACT_ORGANIZATION_GOVERNANCE_SOURCE_ONLY_NOT_ACTIVATION'&&governance.public_activation_allowed===false&&governance.production_effect_authorized===false);
 need(governance.baseline_source_map_sha256===wrangler.effective_source_map_sha256&&governance.effective_source_map_sha256===provenance.org_governance_source_map_sha256);
 const transitionPath='docs/rendezvous/core-governance-transition-source-delta-v1.json';
 const transitionRaw=await readFile(join(repo,transitionPath));
 need(plan.reference_hashes[transitionPath]===sha(transitionRaw)&&sha(transitionRaw)===provenance.core_governance_transition_delta_sha256);
 const transition=JSON.parse(transitionRaw);
 need(transition.scope==='EXACT_CORE_GOVERNANCE_WORKFLOW_TRANSITION_NOT_ACTIVATION'&&transition.public_activation_allowed===false&&transition.production_effect_authorized===false);
 need(transition.baseline_source_map_sha256===governance.effective_source_map_sha256&&transition.effective_source_map_sha256===provenance.core_governance_transition_source_map_sha256);
 const guardPath='docs/rendezvous/api-guard-reference-source-delta-v1.json';
 const guardRaw=await readFile(join(repo,guardPath));
 need(sha(guardRaw)==='a8ab1f34ef94c7c2ea44095d0b990b1d8ce25a59956aef83d32fda06aa38b32a'&&plan.reference_hashes[guardPath]===sha(guardRaw)&&provenance.api_guard_reference_delta_sha256===sha(guardRaw));
 const guard=JSON.parse(guardRaw),guardManifests=['coordinator/installation-principal/source-manifest.json','coordinator/principal-possession/source-manifest.json'];
 need(Object.keys(guard).sort().join(',')==='guard,manifest_changes,production_effect_authorized,public_activation_allowed,schema_version,scope'&&guard.schema_version===1&&guard.scope==='EXACT_API_GUARD_REFERENCE_SOURCE_ONLY_NOT_ACTIVATION'&&guard.public_activation_allowed===false&&guard.production_effect_authorized===false);
 need(Object.keys(guard.manifest_changes).sort().join(',')===guardManifests.join(',')&&Object.keys(guard.guard).sort().join(',')==='after,before,path');
 need(guard.guard.path==='scripts/check_reusable_workflow_refs.sh'&&guard.guard.before==='dd4f8093413999259d55bf950c2237f72d3e459bea0c43fae380b6774b8834b5'&&guard.guard.after==='6b127d78cfdfbcc65669ab43d2ab1967371cb9e136c691d882bf102adf68149c'&&sha(await readFile(join(repo,guard.guard.path)))===guard.guard.after);
 const orgReleasePath='docs/rendezvous/api-org-only-release-source-delta-v1.json';
 const orgReleaseRaw=await readFile(join(repo,orgReleasePath));
 need(sha(orgReleaseRaw)==='9cdcbdcf78e1990adb86daa388feed9bc4f92a40b3140dddce05acf61bd16e00'&&plan.reference_hashes[orgReleasePath]===sha(orgReleaseRaw)&&provenance.api_org_release_delta_sha256===sha(orgReleaseRaw));
 const orgRelease=JSON.parse(orgReleaseRaw),orgReleaseFiles=['.github/workflows/api-worker-post-deployment-smoke.yml','.github/workflows/deploy-api-worker.yml'];
 need(Object.keys(orgRelease).sort().join(',')==='production_effect_authorized,public_activation_allowed,reference_changes,schema_version,scope'&&orgRelease.schema_version===1&&orgRelease.scope==='EXACT_API_ORG_ONLY_RELEASE_SOURCE_NOT_ACTIVATION'&&orgRelease.public_activation_allowed===false&&orgRelease.production_effect_authorized===false);
 need(JSON.stringify(Object.keys(orgRelease.reference_changes).sort())===JSON.stringify(orgReleaseFiles));
 const identityPath='docs/rendezvous/api-core-identity-source-delta-v1.json';
 const identityRaw=await readFile(join(repo,identityPath));
 need(sha(identityRaw)==='dc2ef35dd624d60efb99b3048e3617bc214578e57449dc9e2a73e8901719e2ab'&&plan.reference_hashes[identityPath]===sha(identityRaw)&&provenance.api_core_identity_delta_sha256===sha(identityRaw));
 const identity=JSON.parse(identityRaw);
 need(identity.scope==='EXACT_API_CORE_IDENTITY_SOURCE_ONLY_NOT_ACTIVATION'&&identity.public_activation_allowed===false&&identity.production_effect_authorized===false);
 const authorityPath='docs/rendezvous/api-org-core-authority-source-delta-v1.json';
 const authorityRaw=await readFile(join(repo,authorityPath));
 need(sha(authorityRaw)==='a4a87feb002f94f8a8db3afe3414372ea51ae11b04dd7167f0f832d4c1967de1'&&plan.reference_hashes[authorityPath]===sha(authorityRaw)&&provenance.api_org_core_authority_delta_sha256===sha(authorityRaw));
 const authority=JSON.parse(authorityRaw);
 need(Object.keys(authority).sort().join(',')==='production_effect_authorized,public_activation_allowed,reference_changes,schema_version,scope'&&authority.schema_version===1&&authority.scope==='EXACT_API_ORGANIZATION_CORE_AUTHORITY_NOT_ACTIVATION'&&authority.public_activation_allowed===false&&authority.production_effect_authorized===false&&JSON.stringify(Object.keys(authority.reference_changes).sort())===JSON.stringify(orgReleaseFiles));
 for(const name of orgReleaseFiles){const c=orgRelease.reference_changes[name],a=authority.reference_changes[name],current=await historicalRead(join(repo,name),wrangler4164,'utf8'),oldNames="['pcvantol/djconnect', 'djconnect-music-dj/djconnect']",newNames="['djconnect-music-dj/djconnect']";need(Object.keys(c).sort().join(',')==='after,before'&&c.before===identity.reference_changes[name].after&&Object.keys(a).sort().join(',')==='after,before'&&a.before===c.after&&current.split(newNames).length===2&&sha(Buffer.from(current.replace(newNames,oldNames)))===a.before&&sha(Buffer.from(current))===a.after&&plan.reference_hashes[name]===a.after);}
 const summaryPath='docs/rendezvous/api-governance-summary-pin-source-delta-v1.json';
 const summaryRaw=await readFile(join(repo,summaryPath));
 need(sha(summaryRaw)==='15a78327a997ada80926e8443715787951b2a18967a7ddaac90fa373cd6efd32'&&plan.reference_hashes[summaryPath]===sha(summaryRaw)&&provenance.api_governance_summary_pin_delta_sha256===sha(summaryRaw));
 const summary=JSON.parse(summaryRaw);
 need(Object.keys(summary).sort().join(',')==='manifest_changes,production_effect_authorized,public_activation_allowed,schema_version,scope,workflow_changes'&&summary.schema_version===1&&summary.scope==='EXACT_API_GOVERNANCE_SUMMARY_PIN_SOURCE_ONLY_NOT_ACTIVATION'&&summary.public_activation_allowed===false&&summary.production_effect_authorized===false);
 const canonicalPath='docs/rendezvous/api-canonical-workflow-pin-reset-v1.json',canonicalRaw=await readFile(join(repo,canonicalPath));
 need(sha(canonicalRaw)==='56fde11218670c5e22d23e9fe43eac373cec36e80501eafb563cf668f8369c8e'&&plan.reference_hashes[canonicalPath]===sha(canonicalRaw)&&provenance.canonical_workflow_pin_reset_sha256===sha(canonicalRaw));
 const canonical=JSON.parse(canonicalRaw);
 need(Object.keys(canonical).sort().join(',')==='consumed_blobs,manifest_changes,new_pin,old_pin,production_effect_authorized,public_activation_allowed,schema_version,scope,workflow_changes'&&canonical.schema_version===1&&canonical.scope==='EXACT_CANONICAL_WORKFLOW_PIN_RESET_NOT_ACTIVATION'&&canonical.old_pin==='4025a68add8ba98f1f2e0307d7f3998e45c0d9ef'&&canonical.new_pin==='ef8fe39c66689822887fee3720c7500eaa76955a'&&canonical.public_activation_allowed===false&&canonical.production_effect_authorized===false);
 const canonicalPrevious=(name,raw)=>{
  const change=canonical.workflow_changes[name]||canonical.manifest_changes[name];if(!change)return raw;
  need(sha(Buffer.from(raw))===change.after);
  if(canonical.workflow_changes[name]){
   need(Object.keys(change).sort().join(',')==='after,before,replacements'&&Number.isInteger(change.replacements)&&[1,2].includes(change.replacements));
   const before='@'+canonical.old_pin,after='@'+canonical.new_pin;
   need(raw.split(after).length===change.replacements+1&&!raw.includes(before));raw=raw.split(after).join(before);
  }else{
   need(Object.keys(change).sort().join(',')==='after,before,replacements'&&Array.isArray(change.replacements));const seen=new Set();
   for(const item of change.replacements){const pin=canonical.workflow_changes[item.input];need(Object.keys(item).sort().join(',')==='after,before,input'&&pin&&!seen.has(item.input));seen.add(item.input);const before=JSON.stringify(item.input)+': '+JSON.stringify(pin.before),after=JSON.stringify(item.input)+': '+JSON.stringify(pin.after);need(item.before===before&&item.after===after&&raw.split(after).length===2);raw=raw.replace(after,before);}
  }
  need(sha(Buffer.from(raw))===change.before);return raw;
 };
 const delta41Path='docs/rendezvous/api-4-1-org-policy-source-delta-v1.json',delta41Raw=await readFile(join(repo,delta41Path));
 need(sha(delta41Raw)==='91645102ead4fa549b1b71c5d131516ea14b3024c9213518e27bb1aeee01e010'&&plan.reference_hashes[delta41Path]===sha(delta41Raw)&&provenance.api_41_org_policy_source_delta_sha256===sha(delta41Raw));
 const delta41=JSON.parse(delta41Raw),delta41Workflows=[".github/workflows/ci-cd.yml", ".github/workflows/codeql.yml", ".github/workflows/host-app-wake-receiving.yml", ".github/workflows/host-app-wake-source.yml", ".github/workflows/installation-principal-data.yml", ".github/workflows/installation-registry-transactions.yml", ".github/workflows/native-proof-data-journal.yml", ".github/workflows/native-proof-transcript.yml", ".github/workflows/post-merge-release-evidence.yml", ".github/workflows/principal-possession-data.yml", ".github/workflows/push-coordinator-source.yml", ".github/workflows/reusable-workflow-guard.yml", ".github/workflows/rich-delivery-adapter.yml", ".github/workflows/rich-session-data-profile.yml", ".github/workflows/semgrep.yml", ".github/workflows/surface-enrollment-source.yml", ".github/workflows/trusted-delivery.yml", ".github/workflows/watch-moment-alert-source.yml", ".github/workflows/widget-first-key-source.yml", ".github/workflows/worker-do-registry-source.yml"],delta41Versions=["package-lock.json", "package.json", "scripts/qualify_rendezvous_product_build.mjs", "src/releaseMetadata.ts"];
 need(Object.keys(delta41).sort().join(',')==='production_effect_authorized,public_activation_allowed,schema_version,scope,version_source_changes,workflow_changes'&&delta41.schema_version===1&&delta41.scope==='EXACT_API_4_1_ORGANIZATION_PIN_SOURCE_ONLY_NOT_ACTIVATION'&&delta41.public_activation_allowed===false&&delta41.production_effect_authorized===false);
 need(JSON.stringify(Object.keys(delta41.workflow_changes).sort())===JSON.stringify(delta41Workflows)&&JSON.stringify(Object.keys(delta41.version_source_changes).sort())===JSON.stringify(delta41Versions));
 need(JSON.stringify(Object.keys(canonical.workflow_changes).sort())===JSON.stringify(delta41Workflows));
 const delta41Previous={};
 for(const [name,change] of Object.entries(delta41.workflow_changes)){
  need(Object.keys(change).sort().join(',')==='after,before,replacements'&&Array.isArray(change.replacements)&&change.replacements.length>0);
  let current=canonicalPrevious(name,await historicalRead(join(repo,name),wrangler4164,'utf8'));need(sha(Buffer.from(current))===change.after);
  for(const item of change.replacements){need(Object.keys(item).sort().join(',')==='after,before'&&typeof item.before==='string'&&typeof item.after==='string'&&item.before!==item.after&&current.split(item.after).length===2);current=current.replace(item.after,item.before);}
  need(sha(Buffer.from(current))===change.before);delta41Previous[name]=current;
 }
 for(const [name,change] of Object.entries(delta41.version_source_changes))need(Object.keys(change).sort().join(',')==='after,before'&&sha(await historicalRead(join(repo,name),wrangler4164))===change.after);
 const manifest41Path='docs/rendezvous/api-4-1-manifest-refresh-delta-v1.json',manifest41Raw=await readFile(join(repo,manifest41Path));
 need(sha(manifest41Raw)==='339f9911e7dcd8a7a5d6aaca6edba4dd574261318faf24647aa228429b40f760'&&plan.reference_hashes[manifest41Path]===sha(manifest41Raw)&&provenance.api_41_manifest_refresh_delta_sha256===sha(manifest41Raw));
 const manifest41=JSON.parse(manifest41Raw),manifest41Files=['coordinator/host-app-wake-receiving/runtime/source-inputs.json','coordinator/host-app-wake/source-manifest.json','coordinator/installation-principal/source-manifest.json','coordinator/installation-registry/source-manifest.json','coordinator/principal-possession/source-manifest.json','coordinator/rich-delivery/source-manifest.json','coordinator/rich-session/source-manifest.json','coordinator/source-manifest.json','coordinator/worker-do/source-manifest.json','qualification/watch-moment/source-manifest.json'].sort(),manifest41Previous={};
 need(Object.keys(manifest41).sort().join(',')==='manifest_changes,production_effect_authorized,public_activation_allowed,schema_version,scope'&&manifest41.schema_version===1&&manifest41.scope==='EXACT_API_4_1_ACTIVE_MANIFEST_PINS_NOT_ACTIVATION'&&manifest41.public_activation_allowed===false&&manifest41.production_effect_authorized===false&&JSON.stringify(Object.keys(manifest41.manifest_changes).sort())===JSON.stringify(manifest41Files));
 need(JSON.stringify(Object.keys(canonical.manifest_changes).sort())===JSON.stringify(manifest41Files));
 for(const [name,change] of Object.entries(manifest41.manifest_changes)){
  need(Object.keys(change).sort().join(',')==='after,before,replacements'&&Array.isArray(change.replacements)&&change.replacements.length>0);
  let current=canonicalPrevious(name,await historicalRead(join(repo,name),wrangler4164,'utf8'));need(sha(Buffer.from(current))===change.after);const seen=new Set();
  for(const item of change.replacements){const pin=delta41.workflow_changes[item.input]||delta41.version_source_changes[item.input];need(Object.keys(item).sort().join(',')==='after,before,input'&&pin&&!seen.has(item.input));seen.add(item.input);const before=JSON.stringify(item.input)+': '+JSON.stringify(pin.before),after=JSON.stringify(item.input)+': '+JSON.stringify(pin.after);need(item.before===before&&item.after===after&&current.split(after).length===2);current=current.replace(after,before);}
  need(sha(Buffer.from(current))===change.before);manifest41Previous[name]=current;
 }
 const sharedPath='docs/rendezvous/api-shared-governance-source-delta-v1.json';
 const sharedRaw=await readFile(join(repo,sharedPath));
 need(sha(sharedRaw)==='b9e44f138b5824cc29ca5fd99c3d822491486f2a720bb675303e65dc50a65376'&&plan.reference_hashes[sharedPath]===sha(sharedRaw)&&provenance.api_shared_governance_delta_sha256===sha(sharedRaw));
 const shared=JSON.parse(sharedRaw);
 need(shared.schema_version===1&&shared.scope==='EXACT_API_SHARED_GOVERNANCE_SOURCE_ONLY_NOT_ACTIVATION'&&shared.public_activation_allowed===false&&shared.production_effect_authorized===false);
 const sharedFiles=[".github/workflows/ci-cd.yml",".github/workflows/codeql.yml",".github/workflows/host-app-wake-receiving.yml",".github/workflows/host-app-wake-source.yml",".github/workflows/installation-principal-data.yml",".github/workflows/installation-registry-transactions.yml",".github/workflows/native-proof-data-journal.yml",".github/workflows/native-proof-transcript.yml",".github/workflows/principal-possession-data.yml",".github/workflows/push-coordinator-source.yml",".github/workflows/reusable-workflow-guard.yml",".github/workflows/rich-delivery-adapter.yml",".github/workflows/rich-session-data-profile.yml",".github/workflows/semgrep.yml",".github/workflows/surface-enrollment-source.yml",".github/workflows/watch-moment-alert-source.yml",".github/workflows/widget-first-key-source.yml",".github/workflows/worker-do-registry-source.yml"];
 need(JSON.stringify(Object.keys(shared.workflow_changes).sort())===JSON.stringify(sharedFiles));
 need(JSON.stringify(Object.keys(summary.workflow_changes).sort())===JSON.stringify(sharedFiles));
 const sharedOld='pcvantol/djconnect/.github/workflows/software-assurance-governance.yml@aabd5de46ae438478eb894707e5b1ea27aca8508';
 const sharedNew='djconnect-music-dj/djconnect-shared-workflows/.github/workflows/software-assurance-governance-aabd.yml@b4e6470be61fee895af0e13ca1a63f101f03d647';
 const sharedPrevious={};
 for(const name of sharedFiles){
  const current=delta41Previous[name],latest=summary.workflow_changes[name],change=shared.workflow_changes[name];
  const newest='2a1c6fd2841b08630aee01402850f56840b50f70',previous='b4e6470be61fee895af0e13ca1a63f101f03d647';
  need(Object.keys(latest).sort().join(',')==='after,before'&&current.split(newest).length===2&&sha(Buffer.from(current))===latest.after);
  const text=current.replace(newest,previous);need(sha(Buffer.from(text))===latest.before);
  need(Object.keys(change).sort().join(',')==='after,before'&&text.split(sharedNew).length===2&&sha(Buffer.from(text))===change.after);
  sharedPrevious[name]=text.replace(sharedNew,sharedOld);
  need(sha(Buffer.from(sharedPrevious[name]))===change.before);
 }
 const sharedManifests=["coordinator/host-app-wake-receiving/runtime/source-inputs.json","coordinator/host-app-wake/source-manifest.json","coordinator/installation-principal/source-manifest.json","coordinator/installation-registry/source-manifest.json","coordinator/principal-possession/source-manifest.json","coordinator/rich-delivery/source-manifest.json","coordinator/rich-session/source-manifest.json","coordinator/source-manifest.json","coordinator/worker-do/source-manifest.json","qualification/watch-moment/source-manifest.json"];
 need(JSON.stringify(Object.keys(shared.manifest_changes).sort())===JSON.stringify(sharedManifests));
 need(JSON.stringify(Object.keys(summary.manifest_changes).sort())===JSON.stringify(sharedManifests));
 for(const name of sharedManifests){
  let text=manifest41Previous[name];need(typeof text==='string');
  const latest=summary.manifest_changes[name],latestWorkflow=summary.workflow_changes[latest.workflow];
  need(Object.keys(latest).sort().join(',')==='after,before,workflow'&&latestWorkflow&&sha(Buffer.from(text))===latest.after&&text.split(latestWorkflow.after).length===2);
  text=text.replace(latestWorkflow.after,latestWorkflow.before);need(sha(Buffer.from(text))===latest.before);
  const change=shared.manifest_changes[name],workflow=shared.workflow_changes[change.workflow];need(latest.workflow===change.workflow);
  if(guardManifests.includes(name)){
   const update=guard.manifest_changes[name];
   need(Object.keys(update).sort().join(',')==='after,before'&&sha(Buffer.from(text))===update.after&&latest.before===update.after&&text.split(guard.guard.after).length===2);
   text=text.replace(guard.guard.after,guard.guard.before);
   need(sha(Buffer.from(text))===update.before&&update.before===change.after);
  }
  need(Object.keys(change).sort().join(',')==='after,before,workflow'&&workflow&&text.split(workflow.after).length===2&&sha(Buffer.from(text))===change.after);
  sharedPrevious[name]=text.replace(workflow.after,workflow.before);
  need(sha(Buffer.from(sharedPrevious[name]))===change.before);
 }
 need(JSON.stringify(Object.keys(shared.source_changes))===JSON.stringify(['.github/workflows/ci-cd.yml']));
 const sharedReferenceFiles=['.github/workflows/reusable-workflow-guard.yml',...sharedManifests.filter(name=>name!=='coordinator/source-manifest.json')].sort();
 need(JSON.stringify(Object.keys(shared.reference_changes).sort())===JSON.stringify(sharedReferenceFiles));
 for(const [name,change] of Object.entries({...shared.source_changes,...shared.reference_changes})){
  const entry=shared.workflow_changes[name]||shared.manifest_changes[name];
  need(entry&&change.before===entry.before&&change.after===entry.after&&Object.keys(change).sort().join(',')==='after,before');
 }

 const transitionFiles=[".github/workflows/ci-cd.yml",".github/workflows/host-app-wake-receiving.yml",".github/workflows/host-app-wake-source.yml",".github/workflows/installation-principal-data.yml",".github/workflows/installation-registry-transactions.yml",".github/workflows/native-proof-data-journal.yml",".github/workflows/native-proof-transcript.yml",".github/workflows/principal-possession-data.yml",".github/workflows/push-coordinator-source.yml",".github/workflows/reusable-workflow-guard.yml",".github/workflows/rich-delivery-adapter.yml",".github/workflows/rich-session-data-profile.yml",".github/workflows/surface-enrollment-source.yml",".github/workflows/watch-moment-alert-source.yml",".github/workflows/worker-do-registry-source.yml"];
 need(Object.keys(transition.workflow_changes).length===transitionFiles.length&&transitionFiles.every(name=>Object.hasOwn(transition.workflow_changes,name)));
 const oldGovernance='software-assurance-governance.yml@dd02d6470f061e6e755e6fb47ae5331c34f89875';
 const newGovernance='software-assurance-governance.yml@aabd5de46ae438478eb894707e5b1ea27aca8508';
 for(const name of transitionFiles){
  const text=sharedPrevious[name],change=transition.workflow_changes[name];
  need(text.split(newGovernance).length===2&&sha(Buffer.from(text))===change.after&&sha(Buffer.from(text.replace(newGovernance,oldGovernance)))===change.before);
 }
 need(Object.keys(transition.auxiliary_changes).length===1&&Object.hasOwn(transition.auxiliary_changes,'coordinator/source-manifest.json'));
 need(sha(Buffer.from(sharedPrevious['coordinator/source-manifest.json']))===transition.auxiliary_changes['coordinator/source-manifest.json'].after);
 for(const [name,pin] of Object.entries(root.source_hashes))if(!name.startsWith('node_modules/')){
  let expected=pin;
  if(Object.hasOwn(delta,name)){need(delta[name].before===expected);expected=delta[name].after;}
  if(Object.hasOwn(closed.changes,name)){need(closed.changes[name].before===expected);expected=closed.changes[name].after;}
  if(Object.hasOwn(retention.changes,name)){need(retention.changes[name].before===expected);expected=retention.changes[name].after;}
  if(Object.hasOwn(category.changes,name)){need(category.changes[name].before===expected);expected=category.changes[name].after;}
  if(Object.hasOwn(mount.changes,name)){need(mount.changes[name].before===expected);expected=mount.changes[name].after;}
  if(Object.hasOwn(dependency.source_changes,name)){need(dependency.source_changes[name].before===expected);expected=dependency.source_changes[name].after;}
  if(Object.hasOwn(watch.source_changes,name)){need(watch.source_changes[name].before===expected);expected=watch.source_changes[name].after;}
  if(Object.hasOwn(receipt.source_changes,name)){need(receipt.source_changes[name].before===expected);expected=receipt.source_changes[name].after;}
  if(Object.hasOwn(releaseRetention.changes,name)){need(releaseRetention.changes[name].before===expected);expected=releaseRetention.changes[name].after;}
  if(Object.hasOwn(bindings.changes,name)){need(bindings.changes[name].before===expected);expected=bindings.changes[name].after;}
  if(Object.hasOwn(toolchain.changes,name)){need(toolchain.changes[name].before===expected);expected=toolchain.changes[name].after;}
  if(Object.hasOwn(maintenance.changes,name)){need(maintenance.changes[name].before===expected);expected=maintenance.changes[name].after;}
  if(Object.hasOwn(stable.changes,name)){need(stable.changes[name].before===expected);expected=stable.changes[name].after;}
  if(Object.hasOwn(erasure.changes,name)){need(erasure.changes[name].before===expected);expected=erasure.changes[name].after;}
  if(Object.hasOwn(keyAddress.changes,name)){need(keyAddress.changes[name].before===expected);expected=keyAddress.changes[name].after;}
  if(Object.hasOwn(testFlight.changes,name)){need(testFlight.changes[name].before===expected);expected=testFlight.changes[name].after;}
  if(Object.hasOwn(publicTrial.source_changes,name)){need(publicTrial.source_changes[name].before===expected);expected=publicTrial.source_changes[name].after;}
  if(Object.hasOwn(alwaysOn.source_changes,name)){need(alwaysOn.source_changes[name].before===expected);expected=alwaysOn.source_changes[name].after;}
  if(Object.hasOwn(wrangler.changes,name)){need(wrangler.changes[name].before===expected);expected=wrangler.changes[name].after;}
  if(Object.hasOwn(governance.source_changes,name)){need(governance.source_changes[name].before===expected);expected=governance.source_changes[name].after;}
  if(Object.hasOwn(transition.source_changes,name)){need(transition.source_changes[name].before===expected);expected=transition.source_changes[name].after;}
  if(Object.hasOwn(shared.source_changes,name)){need(shared.source_changes[name].before===expected);expected=shared.source_changes[name].after;}
  if(Object.hasOwn(summary.workflow_changes,name)){need(summary.workflow_changes[name].before===expected);expected=summary.workflow_changes[name].after;}
  const final41=delta41.workflow_changes[name]||delta41.version_source_changes[name];if(final41){need(final41.before===expected);expected=final41.after;}
  if(canonical.workflow_changes[name]){need(canonical.workflow_changes[name].before===expected);expected=canonical.workflow_changes[name].after;}
  if(native.changes[name]){need(native.changes[name].before===expected);expected=native.changes[name].after;}
  need(plan.source_hashes[name]===expected);
 }
 const previousSources={...plan.source_hashes};
 for(const[name,c]of Object.entries(native.changes)){need(previousSources[name]===c.after);previousSources[name]=c.before;}
 for(const[name,pin]of Object.entries(native.additions)){need(previousSources[name]===pin);delete previousSources[name];}
 need(mapHash(previousSources)===native.baseline_source_map_sha256&&mapHash(plan.source_hashes)===native.effective_source_map_sha256&&
  provenance.installation_native_widget_source_delta_sha256===nativeDeltaPin&&provenance.installation_native_widget_source_map_sha256===native.effective_source_map_sha256&&
  publishedPlan.reference_hashes[nativeDeltaPath]===nativeDeltaPin);
 for(const[name,pin]of Object.entries(native.reference_additions))need(plan.reference_hashes[name]===pin);
 need(mapHash(plan.source_hashes)===counter.baseline_source_map_sha256&&counter.baseline_source_map_sha256===native.effective_source_map_sha256&&
  mapHash(counterPublishedSources)===counter.effective_source_map_sha256&&provenance.native_widget_counter_integrity_delta_sha256===counterDeltaPin&&
  provenance.native_widget_counter_integrity_source_map_sha256===counter.effective_source_map_sha256&&publishedPlan.reference_hashes[counterDeltaPath]===counterDeltaPin);
 need(mapHash(counterPublishedSources)===ack.baseline_source_map_sha256&&ack.baseline_source_map_sha256===counter.effective_source_map_sha256&&
  mapHash(ackPublishedSources)===ack.effective_source_map_sha256&&provenance.native_ack_key_bounds_delta_sha256===ackDeltaPin&&
  provenance.native_ack_key_bounds_source_map_sha256===ack.effective_source_map_sha256&&publishedPlan.reference_hashes[ackDeltaPath]===ackDeltaPin);
 need(mapHash(ackPublishedSources)===unique.baseline_source_map_sha256&&unique.baseline_source_map_sha256===ack.effective_source_map_sha256&&
  mapHash(uniquePublishedSources)===unique.effective_source_map_sha256&&provenance.native_apple_identity_uniqueness_delta_sha256===uniqueDeltaPin&&
  provenance.native_apple_identity_uniqueness_source_map_sha256===unique.effective_source_map_sha256&&publishedPlan.reference_hashes[uniqueDeltaPath]===uniqueDeltaPin);
 need(mapHash(uniquePublishedSources)===policy40533.baseline_source_map_sha256&&policy40533.baseline_source_map_sha256===unique.effective_source_map_sha256&&
  mapHash(wrangler4164PreviousSources)===policy40533.effective_source_map_sha256&&provenance.native_ios40533_policy_delta_sha256===policy40533DeltaPin&&
  provenance.native_ios40533_policy_source_map_sha256===policy40533.effective_source_map_sha256&&publishedPlan.reference_hashes[policy40533DeltaPath]===policy40533DeltaPin);
 const pins={...root.source_hashes,...publishedPlan.source_hashes,...publishedPlan.reference_hashes};
 const installed=Object.keys(root.source_hashes).filter(p=>p.startsWith('node_modules/'));need(installed.length===50);
 for(const [name,change] of Object.entries(dependency.installed_changes)){need(name==='node_modules/pkijs/build/index.js'&&pins[name]===change.before);pins[name]=change.after;}
 await checkSourcePins(pins,repo);
 for(const p of toolFiles)pins[p]=sha(await readFile(join(repo,p)));
 const head=gitRead(['rev-parse','HEAD']);need(head.status===0&&/^[0-9a-f]{40}\n$/.test(head.stdout));
 return {head:head.stdout.trim(),pins};
}
export async function startLocalRuntime(){
 return startRuntime(false);
}
export async function startLocal40381Runtime(){
 return startRuntime(true);
}
async function startRuntime(private40381){
 const snapshot=await sourceSnapshot(),scratch=await mkdtemp(join(tmpdir(),'djc-native-local-'));await chmod(scratch,0o700);
 let runtime;
 try{
  const inputs=JSON.parse(await readFile(join(repo,'rendezvous-build-inputs.json')));
  const stage=private40381?await stage40381(snapshot,repo,scratch):undefined;
  const source=stage?.root??repo;
  const bridge=randomBytes(32).toString('base64url');
  const driver=`import {createProductRendezvousHandler} from ${JSON.stringify(join(source,'src/rendezvous/composition.ts'))};
export {RequestAdmission,AllocationBudget,AllocationIndex,EnrollmentCoordinator,BudgetedTransactionCoordinator} from ${JSON.stringify(join(source,'src/index.ts'))};
export default {async fetch(request,env){
 if(request.headers.get('X-Local-Bridge')!==env.LOCAL_BRIDGE)return new Response(null,{status:503});
 const path=new URL(request.url).pathname;
 if(!${JSON.stringify(ROUTES)}.includes(path)||request.method!=='POST')return new Response(null,{status:400});
 const headers=new Headers({'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.20'});
 if(['/create','/poll','/consume','/cancel'].includes(path))headers.set('Origin','https://vibecast.tv');
 const incoming=new Request('https://api.djconnect.dev/v1/rendezvous'+path,{method:'POST',headers,body:request.body,cf:{colo:'AMS'}});
 return createProductRendezvousHandler(env)(incoming);
}};`;
  await writeFile(join(scratch,'driver.ts'),driver,{mode:0o600});
  const aliases=Object.fromEntries(Object.entries(inputs.aliases).map(([k,v])=>[k,resolve(source,v)]));
  if(stage)Object.assign(aliases,{cbor:join(repo,'node_modules/cbor/lib/cbor.js'),asn1js:createRequire(import.meta.url).resolve('asn1js'),pkijs:createRequire(import.meta.url).resolve('pkijs')});
  const config={name:'djc-private-native-local',main:join(scratch,'driver.ts'),compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],workers_dev:false,send_metrics:false,alias:aliases};
  await writeFile(join(scratch,'wrangler.json'),JSON.stringify(config),{mode:0o600});
  const built=spawnSync(process.execPath,[join(repo,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--config',join(scratch,'wrangler.json'),'--outdir',join(scratch,'build'),'--metafile',join(scratch,'meta.json')],{cwd:repo,encoding:'utf8',timeout:120000,env:{...process.env,WRANGLER_SEND_METRICS:'false'}});
  need(built.status===0); // Build output is deliberately never logged (paths/contents may be private).
  const bundle=await readFile(join(scratch,'build/driver.js'),'utf8');
  need(!bundle.includes('SoftwareEnrollment')&&!bundle.includes('SOFTWARE_STUB_COMPOSITION'));
  const metadata=JSON.parse(await readFile(join(scratch,'meta.json')));
  const entry=Object.values(metadata.outputs).find(o=>o.entryPoint);need(entry&&entry.exports.length===6&&entry.exports.includes('default'));
  if(stage){await stage.verify();check40381Graph(metadata,stage,snapshot,repo,scratch);}
  for(const p of Object.keys(metadata.inputs)){
   need(!/(?:-harness|\.check\.|fixtures|pre-qr-replacement-reference)/i.test(p));
   if(p.startsWith('node-built-in-modules:'))continue;
   const absolute=resolve(scratch,p);
   need(absolute===join(scratch,'driver.ts')||Object.hasOwn(snapshot.pins,absolute.slice(repo.length+1))&&absolute.startsWith(repo+'/')||stage&&absolute.startsWith(stage.root+'/')&&Object.hasOwn(stage.pins,absolute.slice(stage.root.length+1)));
  }
  const require=createRequire(import.meta.resolve('wrangler'));
  const {Miniflare,Log,LogLevel,convertV4MiniflareOptions}=require('miniflare');
  const until=Date.now()+900000;
  const bindings={LOCAL_BRIDGE:bridge,RENDEZVOUS_EDGE_POLICY:'djc-direct-edge-identity/1-candidate',RENDEZVOUS_IP_HASH_KEY:randomBytes(32).toString('base64'),RECEIPT_ACTIVE_KEY:randomBytes(32).toString('base64'),COMPOSED_POLICY_ENABLED:'djc-http-composition-qualification/1',REQUEST_POLICY_ENABLED:'djc-request-admission-qualification/2',ALLOCATION_POLICY_ENABLED:'djc-allocation-qualification/1',INDEX_POLICY_ENABLED:'djc-index-qualification/1',ASSERTION_POLICY_ENABLED:'ios-dev-qualification/1',ASSERTION_POLICY_EXPIRES_AT:String(until),ENROLLMENT_POLICY_REVISION:stage?'private-40381-registration-recover/1':'local-native-file-experiment/1'};
  const egress={allowed:0,denied:0};
  const outbound=async request=>{egress[allowedStatusRequest(request)?'allowed':'denied']++;return statusOnlyOutbound(request);};
  runtime=new Miniflare({...convertV4MiniflareOptions({host:'127.0.0.1',inspectorHost:'127.0.0.1',durableObjectsPersist:false,unsafeInspectDurableObjects:true,log:new Log(LogLevel.NONE),workers:[{name:'local-native',compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],modulesRoot:join(scratch,'build'),modules:[{type:'ESModule',path:join(scratch,'build/driver.mjs'),contents:bundle}],bindings,durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([k,className])=>[k,{className,useSQLite:true}])),outboundService:outbound},
   // Separate QA-only positive interception control; no DOs, secrets or arbitrary URL.
   {name:'guard-control',modulesRoot:scratch,modules:[{type:'ESModule',path:join(scratch,'guard.mjs'),contents:"export default {fetch(){return fetch('https://egress-denied.example.invalid/qualification');}}"}],outboundService:outbound}]}),enableDevRegistry:false});
  const url=await runtime.ready;need(url.hostname==='127.0.0.1');
  let inspectorDisabled=false;try{await runtime.getInspectorURL();}catch{inspectorDisabled=true;}need(inspectorDisabled);
  const control=await runtime.getWorker('guard-control');need((await control.fetch('https://local.invalid/')).status===503&&egress.denied===1&&egress.allowed===0);
  egress.denied=0;
  const worker=await runtime.getWorker('local-native');
  need((await worker.fetch('https://local.invalid/attestation/challenge',{method:'POST',body:'{}'})).status===503);
  need((await fetch(new URL('/attestation/challenge',url),{method:'POST',body:'{}',redirect:'manual'})).status===503);
  const send=(route,body)=>worker.fetch('https://local.invalid'+route,{method:'POST',headers:{'X-Local-Bridge':bridge},body});
  const request=stage?registrationRecoverController(send):send;
  return {
   snapshot,bundle_sha256:sha(bundle),
   ...(stage?{private_profile:{...stage.receipt,metafile_sha256:sha(JSON.stringify(metadata))}}:{}),
   egressObservation(){return {...egress};},
   async verifySources(){need(JSON.stringify(await sourceSnapshot())===JSON.stringify(snapshot));if(stage)await stage.verify();need(Date.now()<until);},
   async request(route,body){need(ROUTES.includes(route)&&body instanceof Uint8Array);if(stage){need(Date.now()<until);await stage.verify();}return request(route,body);},
   // Host-only observations, never RPC or wire parameters. Used by negative CI tests.
   async enrollmentObservation(keyId){
    const address=sha(JSON.stringify(['development','ios-dev-qualification/1',keyId]));
    const storage=await runtime.unsafeGetDurableObjectStorage('local-native','EnrollmentCoordinator',{name:'djc-rendezvous-key/1/'+address});
    return {keys:await storage.exec('SELECT COUNT(*) AS n FROM key_state'),operations:await storage.exec('SELECT expires_at,value FROM enrollment_operation')};
   },
   async stop(){await runtime.dispose();await rm(scratch,{recursive:true,force:true});},
  };
 }catch(error){if(runtime)await runtime.dispose();await rm(scratch,{recursive:true,force:true});throw error;}
}
