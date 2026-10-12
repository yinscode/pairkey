/** OWS-style high-level client for all hosted v2 authority sources.
 * Authentication stays source-specific, while key selection, signing and
 * recovery have one application-facing shape. */
import {PairKey} from './hosted-v2.mjs';
import {HostedSession} from './hosted-session.mjs';
import {check, identityKind} from './approval-codec.mjs';
const bytesFromHex=value=>Uint8Array.from(value.slice(2).match(/../g).map(part=>parseInt(part,16)));
const base64=bytes=>btoa(String.fromCharCode(...bytes));

export class PairKeyClient {
  constructor({web3, endpoint, deployment, storage = globalThis.sessionStorage,
    storageKey = 'pairkey-v2-recovery', onProgress, onStage, client,
    ephemeral, assertPasskey} = {}) {
    this.client = client ?? new PairKey({web3, endpoint, deployment, onProgress});
    this.session = new HostedSession(this.client, {storage, storageKey, onStage, ephemeral, assertPasskey});
  }

  /** Connect an account, program, passkey or OIDC authority.
   * `namespace` is a named namespace; `namespaceId` is its raw compatibility form. */
  async connect({source = 'account', wallet, identity, program, mode = 'Offchain',
    namespace, namespaceId, policyScope = 'namespace', credentialId, getIdToken} = {}) {
    check(['account', 'program', 'passkey', 'oidc'].includes(source), 'Unknown PairKey authority source');
    const selection = {namespace, namespaceId};
    if (source === 'account') await this.session.connect(wallet, {...selection, identity});
    if (source === 'program') {
      check(program || identity?.Program, 'A program ID or Program identity is required');
      await this.session.connect(wallet, {...selection, program, mode, identity, policyScope});
    }
    if (source === 'passkey') await this.session.connectPasskey(identity, selection);
    if (source === 'oidc') await this.session.connectOidc(identity, selection);
    this.source = source; this.credentialId = credentialId; this.getIdToken = getIdToken;
    return this.session.namespace;
  }

  async key({chain, path = [0]} = {}) {
    check(chain, 'Choose a destination chain');
    return this.session.loadKey(chain, path);
  }

  async signMessage({chain, path = [0], message, credentialId, getIdToken} = {}) {
    return this.#sign({chain,path,message,credentialId,getIdToken});
  }

  async #sign({chain,path=[0],message='',transaction,credentialId,getIdToken}) {
    check(this.session.namespace, 'Connect an authority first');
    if (!this.session.key || this.session.selection?.chain !== chain
      || JSON.stringify(this.session.selection.path) !== JSON.stringify(path)) await this.key({chain, path});
    const kind = identityKind(this.session.namespace.identity);
    if (kind === 'Passkey') {
      const id = credentialId ?? this.credentialId;
      check(id, 'A passkey credential ID is required');
      return this.#result(await this.session.signPasskey({chain, path, message, transaction}, id));
    }
    if (kind === 'Oidc') {
      const token = getIdToken ?? this.getIdToken;
      check(typeof token === 'function', 'Provide getIdToken({nonce, identity}) for OIDC signing');
      const pending = await this.session.prepareOidc({chain, path, message, transaction});
      const idToken = await token({nonce: pending.ephemeral.oidcNonce, identity: this.session.namespace.identity.Oidc});
      check(typeof idToken === 'string' && idToken.length > 0, 'OIDC provider returned no ID token');
      return this.#result(await this.session.completeOidc(pending, idToken));
    }
    return this.#result(await this.session.sign({chain, path, message, transaction}));
  }

  #result(result){return {jobId:this.session.jobId,publicKeyHex:result.public_key_hex,signatureHex:result.signature_hex,result};}

  async signTransaction({chain, path=[0], transaction, credentialId, getIdToken}={}) {
    check(transaction, 'Provide a destination transaction');
    check(this.session.namespace?.config?.transaction_signing?.[chain]?.sign === true,
      `This PairKey deployment does not advertise ${chain} transaction signing`);
    const original=transaction,wire=this.#wireTransaction(chain,transaction);
    const signed=await this.#sign({chain,path,transaction:wire,credentialId,getIdToken});
    const signedTransaction=this.#assemble(chain,original,signed);
    if(chain==='sui'){
      const value=signed.result?.serialized_signature_hex;
      check(typeof value==='string'&&/^0x[0-9a-f]{194}$/i.test(value),'Sui serialized signature missing');
      const serializedSignature=bytesFromHex(value);
      check(serializedSignature[0]===0,'PairKey currently supports Sui Ed25519 signatures');
      return {...signed,signedTransaction,serializedSignature};
    }
    return {...signed,signedTransaction};
  }

  #wireTransaction(chain,transaction){
    if(chain==='solana'){
      if(transaction.solana)return transaction;
      const message=transaction.message?.serialize?.() ?? transaction.serializeMessage?.();
      check(message,'Provide a Solana Transaction or VersionedTransaction');
      return {solana:{message:[...message]}};
    }
    if(chain==='evm')return transaction.evm_legacy?transaction:{evm_legacy:{transfer:transaction}};
    if(chain==='near'){
      if(transaction.near)return transaction;
      check(transaction instanceof Uint8Array||Array.isArray(transaction),'Provide a Borsh-serialized NEAR transaction');
      return {near:{transaction:[...transaction]}};
    }
    if(chain==='sui'){
      if(transaction.sui)return transaction;
      check(transaction instanceof Uint8Array||Array.isArray(transaction),'Build the Sui transaction first and provide its BCS TransactionData bytes');
      return {sui:{transaction:[...transaction]}};
    }
    throw new Error(`${chain} transaction signing is not implemented`);
  }

  #assemble(chain,original,signed){
    if(chain==='evm'||chain==='near'){
      const hex=signed.result?.signed_transaction_hex;
      check(typeof hex==='string'&&/^0x[0-9a-f]+$/i.test(hex),'Signed transaction encoding missing');
      return Uint8Array.from(hex.slice(2).match(/../g).map(value=>parseInt(value,16)));
    }
    if(chain==='sui')return Uint8Array.from(signed.result.transaction.sui.transaction);
    const signature=Uint8Array.from(signed.signatureHex.slice(2).match(/../g).map(value=>parseInt(value,16)));
    const key=this.client.pubkey(signed.publicKeyHex.slice(2).match(/../g).map(value=>parseInt(value,16)));
    if(!original){
      const bytes=Uint8Array.from(signed.result.transaction.solana.message);
      const message=this.client.web3.VersionedMessage.deserialize(bytes);
      original=new this.client.web3.VersionedTransaction(message);
    }
    if(original.message?.staticAccountKeys&&Array.isArray(original.signatures)){
      const required=original.message.header.numRequiredSignatures;
      const index=original.message.staticAccountKeys.slice(0,required).findIndex(candidate=>candidate.equals(key));
      check(index>=0,'Derived key is not a required Solana signer');
      original.signatures[index]=signature;
      return original.serialize();
    }
    check(Array.isArray(original.signatures)&&original.serialize,'Unsupported Solana transaction object');
    const entry=original.signatures.find(item=>item.publicKey.equals(key));
    check(entry,'Derived key is not a required Solana signer');entry.signature=signature;
    return original.serialize({requireAllSignatures:false,verifySignatures:true});
  }

  async signAndSend(options={}){
    const signed=await this.signTransaction(options);
    return this.#broadcast(signed,options);
  }

  #broadcastKey(jobId){return `${this.session.storageKey}:broadcast:${jobId}`;}
  #saveBroadcast(value){this.session.storage.setItem(this.#broadcastKey(value.job_id),JSON.stringify(value));}
  async #broadcast(signed,options={}){
    let transactionId,status='submitted',receipt=null;
    const chain=options.chain ?? Object.keys(signed.result.transaction)[0].replace('_legacy','');
    const rawHex=[...signed.signedTransaction].map(b=>b.toString(16).padStart(2,'0')).join('');
    const signatureHex=signed.serializedSignature?`0x${[...signed.serializedSignature].map(b=>b.toString(16).padStart(2,'0')).join('')}`:undefined;
    const record={version:1,job_id:signed.jobId,chain,signed_transaction_hex:`0x${rawHex}`,serialized_signature_hex:signatureHex,transaction_id:null,status:'signed',receipt:null,updated_at:new Date().toISOString()};
    // Persist exact signed bytes before touching the destination RPC. A caller
    // can safely recover and rebroadcast this same transaction after a timeout.
    this.#saveBroadcast(record);
    try {
      if(options.broadcast)transactionId=await options.broadcast(signed.signedTransaction,signed);
      else if(chain==='solana'){
        check(options.connection?.sendRawTransaction,'Provide a Solana connection or broadcast callback');
        transactionId=await options.connection.sendRawTransaction(signed.signedTransaction);
        if(options.confirm!==false){receipt=await options.connection.confirmTransaction(transactionId,'confirmed');status=receipt?.value?.err==null?'confirmed':'failed';}
      }else{
        if(chain==='sui'){
          check(signed.serializedSignature,'Sui serialized signature missing');
          check(options.connection?.executeTransaction,'Provide a Sui gRPC client or broadcast callback');
          receipt=await options.connection.executeTransaction({transaction:signed.signedTransaction,signatures:[base64(signed.serializedSignature)],include:{effects:true}});
          const completed=receipt?.Transaction??receipt;
          transactionId=completed?.digest??null;
          status=receipt?.$kind==='FailedTransaction'||completed?.effects?.status?.error?'failed':'confirmed';
        }else{
          check(options.rpcUrl,'Provide a destination RPC URL or broadcast callback');
          const method=chain==='evm'?'eth_sendRawTransaction':'broadcast_tx_commit';
          const value=chain==='evm'?`0x${rawHex}`:base64(signed.signedTransaction);
          const response=await fetch(options.rpcUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:[value]})});
          const body=await response.json();check(response.ok&&!body.error,body.error?.message??'Destination RPC rejected transaction');
          receipt=body.result;transactionId=chain==='evm'?body.result:body.result?.transaction?.hash;
          status=chain==='near'?'confirmed':'submitted';
        }
        if(chain==='evm'&&options.confirm){
          const checkResponse=await fetch(options.rpcUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:2,method:'eth_getTransactionReceipt',params:[transactionId]})});
          const checked=await checkResponse.json();receipt=checked.result;status=receipt?(receipt.status==='0x1'?'confirmed':'failed'):'submitted';
        }
      }
      this.#saveBroadcast({...record,transaction_id:transactionId,status,receipt,updated_at:new Date().toISOString()});
      return {...signed,transactionId,status,receipt};
    } catch(error) {
      const broadcastError=error instanceof Error?error.message:String(error);
      this.#saveBroadcast({...record,status:'unknown',broadcast_error:broadcastError,updated_at:new Date().toISOString()});
      return {...signed,transactionId:null,status:'unknown',receipt:null,broadcastError};
    }
  }

  async recover(jobId) {
    const signed=this.#result(await this.session.recover(jobId));
    if(signed.result.transaction){
      const chain=Object.keys(signed.result.transaction)[0].replace('_legacy','');
      signed.signedTransaction=this.#assemble(chain,undefined,signed);
      if(chain==='sui')signed.serializedSignature=bytesFromHex(signed.result.serialized_signature_hex);
    }
    return signed;
  }

  /** Recover signer output and the last broadcast state without authorizing or signing again.
   * Unknown outcomes may be rebroadcast with the exact same bytes. */
  async recoverAndSend(jobId,options={}){
    const signed=await this.recover(jobId);
    check(signed.signedTransaction,'Recovered job is not a transaction');
    const raw=this.session.storage.getItem(this.#broadcastKey(jobId));
    const previous=raw?JSON.parse(raw):null;
    const currentHex=`0x${[...signed.signedTransaction].map(b=>b.toString(16).padStart(2,'0')).join('')}`;
    check(!previous||previous.signed_transaction_hex===currentHex,'Saved broadcast bytes do not match recovered signer output');
    if(signed.serializedSignature){
      const currentSignature=`0x${[...signed.serializedSignature].map(b=>b.toString(16).padStart(2,'0')).join('')}`;
      check(!previous||previous.serialized_signature_hex===currentSignature,'Saved Sui signature does not match recovered signer output');
    }
    if(previous&&['submitted','confirmed','failed'].includes(previous.status)&&!options.rebroadcast){
      return {...signed,transactionId:previous.transaction_id,status:previous.status,receipt:previous.receipt,recovered:true};
    }
    return {...await this.#broadcast(signed,{...options,chain:options.chain??previous?.chain}),recovered:true};
  }
}
