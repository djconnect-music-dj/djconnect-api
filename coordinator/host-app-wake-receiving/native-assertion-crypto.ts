/** Shared existing assertion crypto only. No key enrollment, SQL permission,
 * counter commit, role ACK or HostWake/native authority is produced here. Both
 * owning writers supply their own actual saved key/policy and independent
 * original once claim + same-transaction counter CAS. */
import cbor from 'cbor';
import * as asn1js from 'asn1js';
import * as pki from 'pkijs';
import {need} from '../host-app-wake/wire';
import {RequestWindow} from './request-window';
const bytes=(s:string)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const digest=async(b:Uint8Array)=>new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(b)));
const concat=(a:Uint8Array,b:Uint8Array)=>{const r=new Uint8Array(a.length+b.length);r.set(a);r.set(b,a.length);return r;};
class InvalidProof extends Error {}
function valid(x:unknown):asserts x {if(!x)throw new InvalidProof();}
function closedMap(v:unknown,keys:(string|number)[]):Map<unknown,unknown>{valid(v instanceof Map&&v.size===keys.length&&keys.every(k=>v.has(k)));return v;}
function decode(b:Uint8Array){return cbor.decodeFirstSync(Buffer.from(b),{preventDuplicateKeys:true,preferMap:true,max_depth:8});}
function signature(raw:unknown):Uint8Array{
 valid(raw instanceof Uint8Array&&raw.length>=8&&raw.length<=72&&raw[0]===0x30&&raw[1]===raw.length-2);
 const d=asn1js.fromBER(Uint8Array.from(raw).buffer);valid(d.offset===raw.length&&!d.result.error&&equal(new Uint8Array(d.result.toBER(false)),raw));
 const seq=d.result;valid(seq instanceof asn1js.Sequence&&seq.valueBlock.value.length===2);
 for(const n of seq.valueBlock.value){valid(n instanceof asn1js.Integer&&!n.idBlock.isConstructed&&n.idBlock.blockLength===1&&n.lenBlock.blockLength===1&&!n.lenBlock.isIndefiniteForm);const b=n.valueBlock.valueHexView;valid(b.length>0&&b.length<=33&&!(b[0]&128)&&b.some(x=>x!==0)&&!(b.length>1&&b[0]===0&&b[1]<128)&&(b.length<33||b[0]===0));}
 const out=new Uint8Array(pki.createECDSASignatureFromCMS(seq,32));valid(out.length===64);return out;
}
export async function verifyNativeAssertionCrypto(encoded:Uint8Array,clientData:Uint8Array,
 key:{public_key_spki_b64:string;native_key_id_b64:string;counter:number},
 p:{profile:string;app_identifier:string;bundle_version:string;launch_validation_category_b64?:string},
 window:RequestWindow):Promise<number|null>{
let auth:Uint8Array,rawSig:Uint8Array,counter:number;
 try{
  const obj=closedMap(decode(encoded),['signature','authenticatorData']);const raw=obj.get('authenticatorData');valid(raw instanceof Uint8Array&&raw.length>=38&&raw.length<=2048);auth=raw;
  valid(auth[32]===0xc0);counter=new DataView(auth.buffer,auth.byteOffset,auth.byteLength).getUint32(33,false);valid(counter>key.counter);
  const props=closedMap(decode(auth.subarray(37)),['apple_bundle_version_01','apple_validation_category_01']);valid(props.get('apple_bundle_version_01')===p.bundle_version);
  const category=props.get('apple_validation_category_01');valid(category instanceof Uint8Array&&equal(category,p.profile==='host_wake_apple_assertion_properties_v2'?bytes(p.launch_validation_category_b64!):new Uint8Array([3,0,0,0])));
  rawSig=signature(obj.get('signature'));
 }catch{return null;}
 // These inputs/algorithms are fixed and trusted. Their exceptions are internal
 // failures, never an invalid-proof verdict or fake service acceptance.
 const appHash=await window.run(()=>digest(new TextEncoder().encode(p.app_identifier)));if(!equal(auth.subarray(0,32),appHash))return null;
 const imported=await window.run(()=>crypto.subtle.importKey('spki',bytes(key.public_key_spki_b64),{name:'ECDSA',namedCurve:'P-256'},true,['verify']));
 const exported=await window.run(()=>crypto.subtle.exportKey('raw',imported));need(exported instanceof ArrayBuffer,'host_wake_native_stored_key',503);const rawPoint=new Uint8Array(exported);
 const keyHash=await window.run(()=>digest(rawPoint));need(equal(keyHash,bytes(key.native_key_id_b64)),'host_wake_native_stored_key_identity',503);
 const clientHash=await window.run(()=>digest(clientData));const nonce=await window.run(()=>digest(concat(auth,clientHash)));
 if(!await window.run(()=>crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},imported,rawSig,nonce)))return null;
 window.check();return counter;
}
