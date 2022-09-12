export type Binary = string;
export type HumanAddr = string;

export interface PreExecutionMsg {
  task_id: number;
  handle: string;
  routing_info: Contract;
  sender_info: Sender;
  payload: Binary;
  nonce: Binary;
  payload_hash: Binary;
  payload_signature: Binary;
  source_network: string;
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
  routing_info: Contract;
  sender: Sender;
  [k: string]: unknown;
}