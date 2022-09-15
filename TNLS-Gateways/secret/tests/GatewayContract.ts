export type Binary = string;
export type HumanAddr = string;

export interface PreExecutionMsg {
  task_id: number;
  source_network: string;
  routing_info: HumanAddr;
  routing_code_hash: string;
  payload: Binary;
  payload_hash: Binary;
  payload_signature: Binary;
  user_address: HumanAddr;
  user_key: Binary;
  handle: string;
  nonce: Binary;
  [k: string]: unknown;
}
export interface Contract {
  address: HumanAddr;
  hash: string;
  [k: string]: unknown;
}
export interface Sender {
  address: HumanAddr;
  public_key: Binary;
  [k: string]: unknown;
}
export interface PostExecutionMsg {
  result: string;
  task_id: number;
  input_hash: Binary;
  [k: string]: unknown;
}
export interface BroadcastMsg {
  result: string;
  payload: Binary;
  task_id: number;
  output_hash: Binary;
  signature: Binary;
  [k: string]: unknown;
}
export interface InitMsg {
  admin?: HumanAddr | null;
  entropy: string;
  [k: string]: unknown;
}
export interface Payload {
  data: string;
  routing_info: string;
  routing_code_hash: string;
  user_address: string;
  user_key: Binary;
  [k: string]: unknown;
}