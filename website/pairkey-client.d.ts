import type * as web3 from '@solana/web3.js';
import type {Chain, KeyResponse, SigningResult, Wallet} from './program-client.d.ts';

export type AuthoritySource = 'account' | 'program' | 'passkey' | 'oidc';
export interface EvmLegacyTransfer {
  chain_id: number; nonce: number; gas_price: number; gas_limit: number; to: number[]; value: number;
}
export interface BitcoinPsbtSpend {
  network: 'testnet'; psbt: number[]; outputs: {value_sats: number; script_pubkey: number[]}[];
  max_fee_sats: number; max_fee_rate_sat_vb: number;
}
export type PairKeyTransaction =
  | web3.Transaction | web3.VersionedTransaction
  | EvmLegacyTransfer | {evm_legacy: {transfer: EvmLegacyTransfer}}
  | Uint8Array | number[] | {near: {transaction: number[]}} | {sui: {transaction: number[]}}
  | BitcoinPsbtSpend | {bitcoin_psbt: {spend: BitcoinPsbtSpend}};
export interface ConnectOptions {
  source?: AuthoritySource;
  wallet?: Wallet;
  identity?: Record<string, unknown>;
  program?: string;
  mode?: 'Onchain' | 'Offchain';
  policyScope?: 'namespace' | 'shared';
  namespace?: string;
  namespaceId?: number[];
  credentialId?: BufferSource;
  getIdToken?: (context: {nonce: string; identity: Record<string, string>}) => Promise<string>;
}
export declare class PairKeyClient {
  constructor(options: {
    web3?: typeof web3;
    endpoint?: string;
    deployment?: Record<string, unknown>;
    storage?: Pick<Storage, 'getItem' | 'setItem'>;
    storageKey?: string;
    onProgress?: (event: Record<string, unknown>) => void;
    onStage?: (stage: string, detail?: Record<string, unknown>) => void;
    client?: unknown;
  });
  connect(options?: ConnectOptions): Promise<Record<string, unknown>>;
  key(options: {chain: Chain; chainId?: number; path?: number[]}): Promise<KeyResponse>;
  signMessage(options: {chain: Chain; chainId?: number; path?: number[]; message: string; credentialId?: BufferSource; getIdToken?: ConnectOptions['getIdToken']}): Promise<SigningResult>;
  signTypedData(options: {chainId: number; path?: number[]; typedData: {types: Record<string, {name: string; type: string}[]>; primaryType: string; domain: {chainId: number; [key: string]: unknown}; message: Record<string, unknown>}; credentialId?: BufferSource; getIdToken?: ConnectOptions['getIdToken']}): Promise<SigningResult & {evmSignatureHex: string}>;
  signTransaction(options: {chain: 'solana' | 'evm' | 'near' | 'sui' | 'bitcoin'; chainId?: number; path?: number[]; transaction: PairKeyTransaction; credentialId?: BufferSource; getIdToken?: ConnectOptions['getIdToken']}): Promise<SigningResult & {signedTransaction: Uint8Array; serializedSignature?: Uint8Array; signedPsbt?: Uint8Array}>;
  signAndSend(options: {chain: 'solana' | 'evm' | 'near' | 'sui' | 'bitcoin'; chainId?: number; path?: number[]; transaction: PairKeyTransaction; connection?: unknown; rpcUrl?: string; confirm?: boolean; broadcast?: (bytes: Uint8Array, signed: SigningResult & {serializedSignature?: Uint8Array}) => Promise<string>}): Promise<SigningResult & {signedTransaction: Uint8Array; serializedSignature?: Uint8Array; transactionId: string | null; status: 'submitted' | 'confirmed' | 'failed' | 'unknown'; receipt: unknown; broadcastError?: string}>;
  recover(jobId?: string): Promise<SigningResult & {signedTransaction?: Uint8Array; serializedSignature?: Uint8Array}>;
  recoverAndSend(jobId: string, options?: {chain?: 'solana' | 'evm' | 'near' | 'sui' | 'bitcoin'; connection?: unknown; rpcUrl?: string; confirm?: boolean; rebroadcast?: boolean; broadcast?: (bytes: Uint8Array, signed: SigningResult & {serializedSignature?: Uint8Array}) => Promise<string>}): Promise<SigningResult & {signedTransaction: Uint8Array; serializedSignature?: Uint8Array; transactionId: string | null; status: string; receipt: unknown; recovered: true}>;
}
