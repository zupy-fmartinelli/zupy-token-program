// Story 37.1 — builds the Codama IDL of zupy-token-program from the handlers' account docs and parse_* offsets.
// Run: npm run build  →  zupy_token_program.json   (then `npm run verify` proves it against lib.rs + real mainnet data)
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import {
  booleanTypeNode, bytesTypeNode, bytesValueNode, definedTypeLinkNode, definedTypeNode, errorNode,
  fieldDiscriminatorNode, fixedSizeTypeNode, instructionAccountNode, instructionArgumentNode, instructionNode,
  numberTypeNode, programNode, publicKeyTypeNode, rootNode, sizePrefixTypeNode, stringTypeNode,
  structFieldTypeNode, structTypeNode,
} from '@codama/nodes';

const PROGRAM_ID = 'ZUPYzr87cgminBywohtbUxnaiFMwXNy8A5pD9cCcvVU';
const u8 = numberTypeNode('u8'), u16 = numberTypeNode('u16'), u32 = numberTypeNode('u32'), u64 = numberTypeNode('u64');
const str = sizePrefixTypeNode(stringTypeNode('utf8'), u32); // parse_string: u32 LE length + UTF-8
const ksuid = fixedSizeTypeNode(bytesTypeNode(), 27);       // parse_bytes::<27>
const rest = bytesTypeNode();                                // trailing V1 TRANSFER (Borsh), remainder of the data
const leafProof = definedTypeLinkNode('leafProof');          // 144 B, parse_leaf_proof_fields

const disc = (name) => createHash('sha256').update(`global:${name}`).digest().subarray(0, 8).toString('hex');
const arg = (name, type, docs) => instructionArgumentNode({ name, type, docs: docs ? [docs] : [] });
// account helper: a(name, flags, docs) with flags "s" signer, "w" writable
const a = (name, flags = '', docs) =>
  instructionAccountNode({ name, isSigner: flags.includes('s'), isWritable: flags.includes('w'), docs: docs ? [docs] : [] });

function ix(name, docs, accounts, args) {
  return instructionNode({
    name,
    docs: [docs],
    discriminators: [fieldDiscriminatorNode('discriminator', 0)],
    accounts,
    arguments: [
      instructionArgumentNode({
        name: 'discriminator',
        type: fixedSizeTypeNode(bytesTypeNode(), 8),
        defaultValue: bytesValueNode('base16', disc(name)),
        defaultValueStrategy: 'omitted',
      }),
      ...args,
    ],
  });
}

const TS = a('tokenState', '', 'Program state PDA ["token_state"]');
const lightTail = [
  a('lightSystemProgram'), a('registeredProgramPda'), a('accountCompressionAuthority'), a('accountCompressionProgram'),
  a('merkleTree', 'w'), a('outputQueue', 'w'),
];
const v1Note = 'Followed by the V1 cToken CPI accounts (fee payer, authority = PDA, Light accounts, trees/queues).';

const returnToPoolAccounts = (entity) => [
  a('transferAuthority', 's'), TS, a('mint'), a(entity, '', 'Leaf owner PDA (signs the CPI)'), a('poolAta', 'w'),
  a('feePayer', 'ws'), a('tokenProgram'), a('systemProgram'), a('compressedTokenProgram'), a('compressedTokenAuthority'),
  a('splInterfacePda', 'w'), ...lightTail,
];

const instructions = [
  ix('initialize_token', 'One-time setup: token_state PDA + Token-2022 mint. Only the treasury (story 36.3).',
    [a('authority', 'ws', 'Must be the treasury'), a('tokenState', 'w'), a('mint', 'ws'), a('poolAta', 'w'),
      a('treasuryAta', 'w'), a('systemProgram'), a('tokenProgram'), a('associatedTokenProgram')],
    [arg('treasury', publicKeyTypeNode()), arg('mintAuthority', publicKeyTypeNode()), arg('transferAuthority', publicKeyTypeNode())]),
  ix('initialize_metadata', 'Initialize the token metadata (treasury).',
    [a('authority', 'ws', 'Treasury'), TS, a('mint', 'w'), a('tokenProgram')],
    [arg('name', str), arg('symbol', str), arg('uri', str)]),
  ix('update_metadata_field', 'Update one metadata field (treasury). field: 0 = name, 1 = symbol, 2 = uri.',
    [a('authority', 'ws', 'Treasury'), TS, a('mint', 'w'), a('tokenProgram')],
    [arg('field', u8), arg('value', str)]),
  ix('mint_tokens', 'Mint Z$ to the treasury ATA within the token_state limits (mint authority).',
    [a('mintAuthority', 'ws'), a('tokenState', 'w'), a('mint', 'w'), a('treasuryAta', 'w'), a('tokenProgram')],
    [arg('amount', u64), arg('memo', str)]),
  ix('treasury_restock_pool', 'Move Z$ from the treasury ATA to the pool ATA (treasury signs).',
    [TS, a('mint'), a('treasuryAta', 'w'), a('poolAta', 'w'), a('treasuryWallet', 's'), a('tokenProgram')],
    [arg('amount', u64), arg('memo', str)]),
  ix('transfer_from_pool', 'Pool → recipient as a compressed leaf (reward).',
    [a('transferAuthority', 's'), TS, a('mint'), a('poolAta', 'w'), a('recipient'), a('feePayer', 'ws'), a('tokenProgram'),
      a('systemProgram'), a('compressedTokenProgram'), a('cpiAuthorityPda'), a('lightSystemProgram'), a('registeredProgramPda'),
      a('noopProgram'), a('accountCompressionAuthority'), a('accountCompressionProgram'), a('splInterfacePda', 'w')],
    [arg('amount', u64), arg('memo', str)]),
  ix('return_to_pool', 'Store PDA compressed balance → pool ATA (decompress with validity proof).',
    returnToPoolAccounts('companyPda'),
    [arg('companyId', u64), arg('amount', u64), arg('companyBump', u8), arg('leafProof', leafProof), arg('memo', str)]),
  ix('transfer_company_to_user', 'Store → customer reward (V1 compressed transfer, hardened; memo = ledger operation id). ' + v1Note,
    [a('transferAuthority', 's'), TS, a('mint'), a('companyPda'), a('userPda'), a('feePayer', 'ws'), a('systemProgram'),
      a('compressedTokenProgram')],
    [arg('companyId', u64), arg('userId', u64), arg('amount', u64), arg('companyBump', u8), arg('userBump', u8),
      arg('memo', str), arg('v1Transfer', rest, 'V1 cToken TRANSFER instruction data (validated on-chain)')]),
  ix('transfer_user_to_company', 'Customer → store spend (V1 compressed transfer). ' + v1Note,
    [a('transferAuthority', 's'), TS, a('mint'), a('userPda'), a('companyPda'), a('feePayer', 'ws'), a('systemProgram'),
      a('compressedTokenProgram')],
    [arg('userId', u64), arg('companyId', u64), arg('amount', u64), arg('userBump', u8), arg('companyBump', u8),
      arg('memo', str), arg('v1Transfer', rest, 'V1 cToken TRANSFER instruction data (validated on-chain)')]),
  ix('execute_split_transfer', 'Customer redemption split: store + incentive pool legs. ' + v1Note,
    [a('transferAuthority', 's'), TS, a('mint'), a('userPda'), a('companyPda'), a('incentivePoolPda'), a('feePayer', 'ws'),
      a('systemProgram'), a('compressedTokenProgram')],
    [arg('userId', u64), arg('companyId', u64), arg('companyAmount', u64), arg('poolAmount', u64), arg('userBump', u8),
      arg('companyBump', u8), arg('incentiveBump', u8), arg('operationType', str),
      arg('v1Transfer', rest, 'V1 cToken TRANSFER instruction data (validated on-chain)')]),
  ix('initialize_rate_limit', 'Create the rate-limit PDA of an authority.',
    [a('authority', 'ws'), a('rateLimitState', 'w'), a('systemProgram')], []),
  ix('set_paused', 'Pause / unpause (treasury).', [a('authority', 's', 'Treasury'), a('tokenState', 'w')],
    [arg('paused', booleanTypeNode())]),
  ix('create_zupy_card', 'Mint the customer loyalty card NFT (mint authority).',
    [a('userPda'), a('zupyCard', 'w'), a('mint', 'w'), a('tokenAccount', 'w'), TS, a('payer', 'ws'), a('tokenProgram'),
      a('associatedTokenProgram'), a('systemProgram')],
    [arg('userKsuid', ksuid), arg('metadataUri', str)]),
  ix('create_coupon_nft', 'Mint a coupon NFT to the customer PDA (mint authority).',
    [a('userPda'), a('couponMint', 'w'), a('couponAta', 'w'), TS, a('payer', 'ws'), a('tokenProgram'),
      a('associatedTokenProgram'), a('systemProgram')],
    [arg('userKsuid', ksuid), arg('couponKsuid', ksuid), arg('metadataUri', str)]),
  ix('mint_coupon_cnft', 'Mint a compressed coupon NFT via Bubblegum (mint authority pays).',
    [a('treeAuthority', 'ws'), a('leafOwner'), a('merkleTree', 'w'), a('treeConfig', 'w'), a('payer', 'ws'),
      a('bubblegumProgram'), a('compressionProgram'), a('logWrapper'), a('systemProgram'), TS],
    [arg('name', str), arg('symbol', str), arg('uri', str)]),
  ix('withdraw_to_external', 'Customer compressed balance → external wallet ATA (decompress with validity proof).',
    [a('transferAuthority', 's'), TS, a('mint'), a('userPda'), a('destWallet'), a('destAta', 'w'), a('feePayer', 'ws'),
      a('tokenProgram'), a('associatedTokenProgram'), a('systemProgram'), a('compressedTokenProgram'),
      a('compressedTokenAuthority'), a('splInterfacePda', 'w'), ...lightTail],
    [arg('amount', u64), arg('userId', u64), arg('userBump', u8), arg('leafProof', leafProof), arg('memo', str)]),
  ix('return_user_to_pool', 'Customer PDA compressed balance → pool ATA (decompress with validity proof).',
    returnToPoolAccounts('userPda'),
    [arg('userId', u64), arg('amount', u64), arg('userBump', u8), arg('leafProof', leafProof), arg('memo', str)]),
  ix('consolidate_leaves', 'Merge 2..8 compressed leaves of one owner into one (same owner, exact sum). ' + v1Note,
    [a('transferAuthority', 's'), TS, a('mint'), a('ownerPda')],
    [arg('ownerKind', u8, '0 = customer (user PDA), 1 = store (company PDA)'), arg('ownerId', u64), arg('ownerBump', u8),
      arg('amount', u64), arg('memo', str), arg('v1Transfer', rest, 'V1 cToken TRANSFER instruction data (validated on-chain)')]),
];

const errors = [
  'InvalidAuthority', 'DailyLimitExceeded', 'TxLimitExceeded', 'AlreadyInitialized', 'InsufficientBalance', 'InvalidAmount',
  'RateLimitNotInitialized', 'InvalidPDA', 'DuplicateMemo', 'InvalidMemoFormat', 'NotInitialized', 'InvalidMint', 'ZeroAmount',
  'InvalidMetadataName', 'InvalidMetadataSymbol', 'InvalidMetadataUri', 'ExtensionCalculationError', 'InvalidPoolAccount',
  'SystemPaused', 'UnauthorizedTreasury', 'ExceedsTransactionLimit', 'ExceedsDailyLimit', 'InvalidTreasuryAccount',
  'InvalidIncentivePool', 'InsufficientPoolBalance', 'InvalidTokenProgram', 'NotImplemented', 'InvalidMetadataPDA',
  'InvalidOperationType', 'SplitCalculationError',
].map((name, i) => errorNode({ name, code: 6000 + i, message: name.replace(/([a-z])([A-Z])/g, '$1 $2') }));

const root = rootNode(programNode({
  name: 'zupyTokenProgram',
  publicKey: PROGRAM_ID,
  version: '1.4.0',
  origin: undefined,
  docs: ['ZUPY (Z$) loyalty token program — Pinocchio. Source: https://github.com/zupy-fmartinelli/zupy-token-program'],
  instructions,
  definedTypes: [definedTypeNode({
    name: 'leafProof',
    docs: ['Leaf being spent + validity proof (144 bytes)'],
    type: structTypeNode([
      structFieldTypeNode({ name: 'leafAmount', type: u64 }), structFieldTypeNode({ name: 'version', type: u8 }),
      structFieldTypeNode({ name: 'leafIndex', type: u32 }), structFieldTypeNode({ name: 'rootIndex', type: u16 }),
      structFieldTypeNode({ name: 'proveByIndex', type: booleanTypeNode() }),
      structFieldTypeNode({ name: 'proof', type: fixedSizeTypeNode(bytesTypeNode(), 128) }),
    ]),
  })],
  errors,
}));

writeFileSync(new URL('./zupy_token_program.json', import.meta.url), JSON.stringify(root, null, 2) + '\n');
console.log(`wrote zupy_token_program.json — ${instructions.length} instructions, ${errors.length} errors`);
