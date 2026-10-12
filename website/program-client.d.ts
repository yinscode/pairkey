import type * as web3 from '@solana/web3.js';

export type Chain = 'solana' | 'evm' | 'zcash' | 'near' | 'bitcoin' | 'sui';
export type ApprovalMode = 'Onchain' | 'Offchain';
export interface Wallet {
  publicKey: web3.PublicKey;
  connect(): Promise<unknown>;
  signMessage(message: Uint8Array, display?: string): Promise<{signature: Uint8Array} | Uint8Array>;
  signTransaction(transaction: web3.Transaction): Promise<web3.Transaction>;
}
export interface KeyResponse {
  public_key_hex: string;
  public_key: number[];
  address?: string | null;
  [field: string]: unknown;
}
export interface Transcript {
  request: unknown;
  approval: unknown;
  key: KeyResponse;
  result: Record<string, unknown>;
  identities: number[][];
}
export interface VerificationStatus {
  browserContext: true;
  serviceSignature: true;
  independentReceipts: boolean;
}
export interface SigningResult {
  jobId: string;
  publicKeyHex: string;
  signatureHex: string;
  result: Record<string, unknown>;
  /** Public input accepted by the repository's independent Rust verifier. */
  transcript: Transcript;
  verification: VerificationStatus;
}
export interface ProgramClientOptions {
  web3: typeof web3;
  wallet: Wallet;
  programId?: string;
  source?: Record<string, unknown>;
  sourceProvider?: (context: Record<string, unknown>) => Promise<Record<string, unknown>>;
  policyAdapter?: {
    read?: (context: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
    set?: (context: Record<string, unknown>) => Promise<{transactionSignature: string; revision: number}>;
    commit?: (context: Record<string, unknown>) => Promise<unknown>;
  };
  mode?: ApprovalMode;
  /** Namespace is the safer default; shared reuses one policy PDA across this owner's namespaces. */
  policyScope?: 'namespace' | 'shared';
  endpoint?: string;
  deployment?: Record<string, unknown>;
  storage?: Pick<Storage, 'getItem' | 'setItem'>;
  storageKey?: string;
  onProgress?: (event: {stage: string; message?: string; signature?: string}) => void;
  onStage?: (stage: string, detail?: Record<string, unknown>) => void;
  /** Return true only after independently checking key, signature and both receipts. */
  verifyTranscript?: (transcript: Transcript) => Promise<boolean> | boolean;
}
export declare class ProgramClient {
  constructor(options: ProgramClientOptions);
  connect(options?: {namespace?: string; namespaceId?: number[]}): Promise<Record<string, unknown>>;
  policy(): Promise<Record<string, unknown> | null>;
  /** Sends an explicit owner-signed Solana transaction; never called by signMessage. */
  setPolicy(options: {
    chain: Chain;
    pathPrefix: number[];
    maxPayloadBytes?: number;
    remainingApprovals?: number;
    enabled?: boolean;
  }): Promise<{transactionSignature: string; revision: number}>;
  deriveKey(options: {chain: Chain; path?: number[]}): Promise<KeyResponse>;
  signMessage(options: {chain: Chain; path?: number[]; message: string}): Promise<SigningResult>;
  signTransaction(options: {chain: 'solana' | 'evm' | 'near' | 'sui'; path?: number[]; transaction: unknown}): Promise<SigningResult>;
  /** Reads the same saved job without a new wallet prompt, commit or signing attempt. */
  recover(jobId?: string): Promise<SigningResult>;
  /** Broadcasts native Ed25519 verification on Solana; does not transfer assets. */
  verifyOnSolana(signed: SigningResult): Promise<{transactionSignature: string}>;
}
