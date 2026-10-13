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
check(reserved.length === 4, `lib.rs reserved discriminators = ${reserved.length}, expected 4 (regex drift would silently skip the reserved check)`);
const idlDiscs = new Set();
for (const ixn of program.instructions) {
  const name = snake(ixn.name);
  const d = ixn.arguments.find((x) => x.name === 'discriminator')?.defaultValue?.data;
  idlDiscs.add(d);
  check(d === disc(name), `${name}: IDL discriminator ${d} != sha256 ${disc(name)}`);
  check(arms.get(d) === name, `${name}: lib.rs dispatches ${d} to ${arms.get(d)}`);
  check(!reserved.includes(d), `${name}: discriminator is RESERVED in lib.rs`);
}
check(program.instructions.length === arms.size, `IDL has ${program.instructions.length} instructions, lib.rs ${arms.size} live arms`);
for (const r of reserved) check(!idlDiscs.has(r), `reserved discriminator ${r} is present in the IDL`);
for (const [d, h] of arms) check(idlDiscs.has(d), `lib.rs live arm ${h} (${d}) missing from the IDL`);
console.log(`(a) ${program.instructions.length} IDL instructions vs ${arms.size} live arms, ${reserved.length} reserved`);

// (b) real mainnet data
const le = (b, o, n) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; };
const str = (b, o) => { const n = Number(le(b, o, 4)); return [Buffer.from(b.subarray(o + 4, o + 4 + n)).toString('utf8'), o + 4 + n]; };
const big = (x) => BigInt(x);
// leaf/proof block (144 B): leaf_amount u64 | version u8 | leaf_index u32 | root_index u16 | prove_by_index bool | proof [u8;128]
// the dynamic codecs return `bytes` values as a [encoding, text] tuple, e.g. ['base64', '...']
const bytesOf = (x) => (Array.isArray(x) ? Buffer.from(x[1], x[0]) : Buffer.from(x));
const hex = (x) => bytesOf(x).toString('hex');
const leafChecks = (b, d, o) => [[big(d.leafProof.leafAmount), le(b, o, 8)], [d.leafProof.version, b[o + 8]],
  [big(d.leafProof.leafIndex), le(b, o + 9, 4)], [d.leafProof.rootIndex, Number(le(b, o + 13, 2))],
  [d.leafProof.proveByIndex, b[o + 15] !== 0], [hex(d.leafProof.proof), hex(b.subarray(o + 16, o + 144))]];
const EXPECT = {
  transfer_company_to_user: (b, d) => [[big(d.companyId), le(b, 0, 8)], [big(d.userId), le(b, 8, 8)], [big(d.amount), le(b, 16, 8)],
    [d.companyBump, b[24]], [d.userBump, b[25]], [d.memo, str(b, 26)[0]], [bytesOf(d.v1Transfer).length, b.length - str(b, 26)[1]]],
  transfer_user_to_company: (b, d) => [[big(d.userId), le(b, 0, 8)], [big(d.companyId), le(b, 8, 8)], [big(d.amount), le(b, 16, 8)],
    [d.userBump, b[24]], [d.companyBump, b[25]], [d.memo, str(b, 26)[0]], [bytesOf(d.v1Transfer).length, b.length - str(b, 26)[1]]],
  transfer_from_pool: (b, d) => [[big(d.amount), le(b, 0, 8)], [d.memo, str(b, 8)[0]]],
  return_to_pool: (b, d) => [[big(d.companyId), le(b, 0, 8)], [big(d.amount), le(b, 8, 8)], [d.companyBump, b[16]],
    ...leafChecks(b, d, 17), [d.memo, str(b, 161)[0]]],
  return_user_to_pool: (b, d) => [[big(d.userId), le(b, 0, 8)], [big(d.amount), le(b, 8, 8)], [d.userBump, b[16]],
    ...leafChecks(b, d, 17), [d.memo, str(b, 161)[0]]],
  withdraw_to_external: (b, d) => [[big(d.amount), le(b, 0, 8)], [big(d.userId), le(b, 8, 8)], [d.userBump, b[16]],
    ...leafChecks(b, d, 17), [d.memo, str(b, 161)[0]]],
  execute_split_transfer: (b, d) => [[big(d.userId), le(b, 0, 8)], [big(d.companyAmount), le(b, 16, 8)],
    [big(d.poolAmount), le(b, 24, 8)], [big(d.companyId), le(b, 8, 8)], [d.userBump, b[32]], [d.companyBump, b[33]],
    [d.incentiveBump, b[34]], [d.operationType, str(b, 35)[0]], [bytesOf(d.v1Transfer).length, b.length - str(b, 35)[1]]],
  consolidate_leaves: (b, d) => [[d.ownerKind, b[0]], [big(d.ownerId), le(b, 1, 8)], [d.ownerBump, b[9]], [big(d.amount), le(b, 10, 8)],
    [d.memo, str(b, 18)[0]], [bytesOf(d.v1Transfer).length, b.length - str(b, 18)[1]]],
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
  const nAcc = node.accounts.length;
  check(s.n_accounts >= nAcc, `${s.name} ${s.signature}: tx passed ${s.n_accounts} accounts, IDL names ${nAcc}`);
  check(!!EXPECT[s.name], `${s.name}: no independent byte-read check defined for this type`);
  seen[s.name] = (seen[s.name] ?? 0) + 1;
}
// AC2: these types MUST be sampled; a type missing from the samples would otherwise pass silently.
const REQUIRED = ['transfer_company_to_user', 'transfer_from_pool', 'return_to_pool', 'mint_coupon_cnft',
  'execute_split_transfer', 'consolidate_leaves'];
for (const t of REQUIRED) check((seen[t] ?? 0) > 0, `${t}: no real mainnet sample (AC2 requires one)`);
check(lines.length > 0, 'samples file is empty');
const unsampled = program.instructions.map((i) => snake(i.name)).filter((n) => !seen[n]);
console.log('    not covered by real data (layout checked against source only):', unsampled.join(', ') || 'none');
console.log('(b) real mainnet samples decoded:', seen);
if (fail.length) { console.error(`FAIL (${fail.length}):\n  ` + fail.slice(0, 30).join('\n  ')); process.exit(1); }
console.log('OK: IDL matches lib.rs and decodes every real sample exactly');
