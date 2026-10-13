// Story 37.1 — proves zupy_token_program.json against the program source and REAL mainnet instruction data.
// (a) every IDL discriminator = sha256("global:<name>")[..8] AND is a live arm of src/lib.rs dispatching to that handler;
//     every live arm is in the IDL; reserved discriminators are not.
// (b) every sample in samples/mainnet-ix.jsonl decodes with the IDL, re-encodes to the SAME bytes (whole data consumed,
//     exact layout), and key fields equal an independent little-endian byte read.
// Usage: npm run verify [-- path/to/idl.json]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { getNodeCodec } from '@codama/dynamic-codecs';
import { parseInstructionData } from '@codama/dynamic-parsers';

const idlPath = process.argv[2] ?? new URL('./zupy_token_program.json', import.meta.url);
const root = JSON.parse(readFileSync(idlPath, 'utf8'));
const program = root.program;
const lib = readFileSync(new URL('../src/lib.rs', import.meta.url), 'utf8');
const fail = [];
const check = (ok, msg) => { if (!ok) fail.push(msg); };
const snake = (s) => s.replace(/[A-Z]/g, (c) => '_' + c.toLowerCase());
const disc = (name) => createHash('sha256').update(`global:${name}`).digest().subarray(0, 8).toString('hex');

// (a) discriminators vs lib.rs
const arms = new Map();
for (const m of lib.matchAll(/\[(\d+(?:,\s*\d+){7})\]\s*=>\s*\{\s*instructions::(\w+)::process/g)) {
  arms.set(Buffer.from(m[1].split(',').map(Number)).toString('hex'), m[2]);
}
const reserved = [...lib.matchAll(/pub const RESERVED_\w+: \[u8; 8\] = \[([\d,\s]+)\]/g)]
  .map((m) => Buffer.from(m[1].split(',').map(Number)).toString('hex'));
check(arms.size === 18, `lib.rs live arms = ${arms.size}, expected 18`);
const idlDiscs = new Set();
for (const ixn of program.instructions) {
  const name = snake(ixn.name);
  const d = ixn.arguments.find((x) => x.name === 'discriminator')?.defaultValue?.data;
  idlDiscs.add(d);
  check(d === disc(name), `${name}: IDL discriminator ${d} != sha256 ${disc(name)}`);
  check(arms.get(d) === name, `${name}: lib.rs dispatches ${d} to ${arms.get(d)}`);
  check(!reserved.includes(d), `${name}: discriminator is RESERVED in lib.rs`);
}
for (const [d, h] of arms) check(idlDiscs.has(d), `lib.rs live arm ${h} (${d}) missing from the IDL`);
console.log(`(a) ${program.instructions.length} IDL instructions vs ${arms.size} live arms, ${reserved.length} reserved`);

// (b) real mainnet data
const le = (b, o, n) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; };
const str = (b, o) => { const n = Number(le(b, o, 4)); return [Buffer.from(b.subarray(o + 4, o + 4 + n)).toString('utf8'), o + 4 + n]; };
const big = (x) => BigInt(x);
const EXPECT = {
  transfer_company_to_user: (b, d) => [[big(d.companyId), le(b, 0, 8)], [big(d.userId), le(b, 8, 8)], [big(d.amount), le(b, 16, 8)],
    [d.companyBump, b[24]], [d.userBump, b[25]], [d.memo, str(b, 26)[0]]],
  transfer_user_to_company: (b, d) => [[big(d.userId), le(b, 0, 8)], [big(d.amount), le(b, 16, 8)], [d.memo, str(b, 26)[0]]],
  transfer_from_pool: (b, d) => [[big(d.amount), le(b, 0, 8)], [d.memo, str(b, 8)[0]]],
  return_to_pool: (b, d) => [[big(d.companyId), le(b, 0, 8)], [big(d.amount), le(b, 8, 8)], [d.companyBump, b[16]],
    [big(d.leafProof.leafAmount), le(b, 17, 8)], [d.memo, str(b, 161)[0]]],
  return_user_to_pool: (b, d) => [[big(d.userId), le(b, 0, 8)], [big(d.amount), le(b, 8, 8)], [d.memo, str(b, 161)[0]]],
  withdraw_to_external: (b, d) => [[big(d.amount), le(b, 0, 8)], [big(d.userId), le(b, 8, 8)], [d.memo, str(b, 161)[0]]],
  execute_split_transfer: (b, d) => [[big(d.userId), le(b, 0, 8)], [big(d.companyAmount), le(b, 16, 8)],
    [big(d.poolAmount), le(b, 24, 8)], [d.operationType, str(b, 35)[0]]],
  consolidate_leaves: (b, d) => [[d.ownerKind, b[0]], [big(d.ownerId), le(b, 1, 8)], [big(d.amount), le(b, 10, 8)], [d.memo, str(b, 18)[0]]],
  mint_coupon_cnft: (b, d) => { const [n, o] = str(b, 0); const [s, o2] = str(b, o); return [[d.name, n], [d.symbol, s], [d.uri, str(b, o2)[0]]]; },
  mint_tokens: (b, d) => [[big(d.amount), le(b, 0, 8)], [d.memo, str(b, 8)[0]]],
};
const samplesUrl = new URL('./samples/mainnet-ix.jsonl', import.meta.url);
const lines = readFileSync(samplesUrl, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const seen = {};
for (const s of lines) {
  const bytes = Uint8Array.from(Buffer.from(s.data_hex, 'hex'));
  const parsed = parseInstructionData(root, bytes, { programAddress: program.publicKey });
  if (!parsed) { fail.push(`${s.name} ${s.signature}: not identified`); continue; }
  const node = parsed.path[parsed.path.length - 1];
  check(snake(node.name) === s.name, `${s.signature}: identified as ${snake(node.name)}, sample is ${s.name}`);
  const re = getNodeCodec(parsed.path).encode(parsed.data);
  check(Buffer.from(re).equals(Buffer.from(bytes)), `${s.name} ${s.signature}: re-encode differs (${re.length} vs ${bytes.length} B)`);
  const body = bytes.subarray(8);
  for (const [got, want] of (EXPECT[s.name]?.(body, parsed.data) ?? [])) {
    check(got === want, `${s.name} ${s.signature}: decoded ${got} != byte read ${want}`);
  }
  seen[s.name] = (seen[s.name] ?? 0) + 1;
}
console.log('(b) real mainnet samples decoded:', seen);
if (fail.length) { console.error(`FAIL (${fail.length}):\n  ` + fail.slice(0, 30).join('\n  ')); process.exit(1); }
console.log('OK: IDL matches lib.rs and decodes every real sample exactly');
