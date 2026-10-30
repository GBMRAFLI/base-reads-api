// Sell simulation + pre-sign verdict: pure unit tests (no network; rpc and lookups are stubs, keys are ephemeral in-memory).
import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1";
import { decodeRevert, decodeRun, factoryAddr, selectUsable, INITIALIZE_TOPIC, parseInitializeLog, poolId, signProof, taxes, verifyProof, word, virtualQuote } from "../lib/sellsim.ts";
import { HELPER_SOURCE_SHA256 } from "../lib/sellsim_helper.ts";
import { call, decode, encode, selector } from "../lib/abi.ts";
import { decodeTx, evaluate, MAX_UINT, presign, signPresign, txSimOverrides, v3Path, type Facts } from "../lib/presign.ts";
import { makeFallbackRpc, readCapped } from "../tools/sellsim.ts";
import { keyIdOf, type Signer } from "../lib/attestation.ts";

const ETH = "0x0000000000000000000000000000000000000000";
const WORTH = "0xb200000000000000000000585fd80c20af698f01", HOOK = "0x985c14baa2a18316ffda0aefb3a632fadfca2acc";
const BRETT = "0x532f27101965dd16442e59d40670faf5ebb142e4", UR = "0x6ff5693b99212da76ad316178a184ab56d299b43";

Deno.test("poolId matches on-chain v4 ids (hooked and hookless)", () => {
  assertEquals(poolId({ currency0: ETH, currency1: WORTH, fee: 0, tickSpacing: 200, hooks: HOOK }), "0x6cf637a82362d304dfa56a6387fc8f909ec0008ec520ee5fb999506d9b1f3514");
  assertEquals(poolId({ currency0: ETH, currency1: "0xed664536023d8e4b1640c394777d34abaff1df8f", fee: 10000, tickSpacing: 200, hooks: ETH }), "0x7c84276e317f128b55bd270dbfba3ef94c84b984c124a1de7c4f72da90bfba45");
});
Deno.test("parseInitializeLog decodes key, negative tickSpacing and rejects junk", () => {
  const id = "0x" + "ab".repeat(32);
  const l = { topics: [INITIALIZE_TOPIC, id, "0x" + word(ETH), "0x" + word(WORTH)], data: "0x" + word(3000) + word((1n << 256n) - 60n) + word(HOOK) + word(1n << 96n) + word(0), blockNumber: "0x10" };
  const p = parseInitializeLog(l)!; assertEquals(p.key, { currency0: ETH, currency1: WORTH, fee: 3000, tickSpacing: -60, hooks: HOOK }); assertEquals(p.block, 16);
  assertEquals(parseInitializeLog({ ...l, topics: l.topics.slice(0, 3) }), null);
  assertEquals(parseInitializeLog({ ...l, topics: ["0x" + "00".repeat(32), ...l.topics.slice(1)] }), null);
  assertEquals(parseInitializeLog({ ...l, data: "0x" + word(1) }), null);
});
Deno.test("decodeRevert: Error(string), panic, ascii, empty, custom", () => {
  assertEquals(decodeRevert(call("Error(string)", ["SPL"])).message, "SPL");
  assertEquals(decodeRevert("0x4e487b71" + word(0x32)).message, "panic_0x32");
  assertEquals(decodeRevert("0x7a65726f5f7265636569766564").message, "zero_received");
  assertEquals(decodeRevert("0x").message, "empty_revert");
  const c = decodeRevert("0xdeadbeef00"); assertEquals(c.selector, "0xdeadbeef"); assertEquals(c.message, null);
});
const runRet = (stage: number, r: bigint[], err = "0x") => "0x" + encode(["uint8", "bytes", "uint256[9]"], [stage, err, r]);
Deno.test("decodeRun + taxes: clean, taxed, sell revert, sell zero", () => {
  const d = decodeRun(runRet(0, [1000n, 500n, 500n, 500n, 500n, 990n, 990n, 1n, 2n])); assertEquals(d.stage, 0); assertEquals(d.r[5], 990n);
  assertEquals(taxes(d.r, 0), { buy_tax: 0, sell_tax: 0 });
  // 5% buy tax; sell: 10% skimmed on the way in, 10% on the way out -> 1 - 0.9*0.9 = 0.19
  assertEquals(taxes([1000n, 1000n, 950n, 950n, 855n, 100n, 90n, 0n, 0n], 0), { buy_tax: 0.05, sell_tax: 0.19 });
  const rv = decodeRun(runRet(2, [1000n, 500n, 500n, 500n, 0n, 0n, 0n, 0n, 0n], call("Error(string)", ["no"])));
  assertEquals(rv.stage, 2); assertEquals(decodeRevert(rv.err).message, "no"); assertEquals(taxes(rv.r, 2).sell_tax, null);
  assertEquals(taxes([1n, 1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n], 3).sell_tax, 1);
  let threw = false; try { decodeRun("0x" + word(0)); } catch { threw = true; } assert(threw);
});
Deno.test("virtualQuote both orientations", () => {
  const Q = 1n << 96n; assertEquals(virtualQuote(10n ** 18n, Q, true), 10n ** 18n); assertEquals(virtualQuote(10n ** 18n, 2n * Q, false), 2n * 10n ** 18n); assertEquals(virtualQuote(1n, 0n, true), 0n);
});
Deno.test("helper source hash matches generated module", async () => {
  const src = await Deno.readFile(new URL("../../contracts/SellSimHelper.sol", import.meta.url));
  const h = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", src)), (b) => b.toString(16).padStart(2, "0")).join("");
  assertEquals(h, HELPER_SOURCE_SHA256);
});
Deno.test("abi encode/decode roundtrip incl. dynamic tuple", () => {
  assertEquals(selector("approve(address,uint256)"), "0x095ea7b3"); assertEquals(selector("transfer(address,uint256)"), "0xa9059cbb");
  const t = ["((address,address,uint24,int24,address),bool,uint128,uint128,bytes)"];
  const v = [[[ETH, WORTH, 0n, -200n, HOOK], true, 5n, 0n, "0xabcd"]];
  assertEquals(decode(t, encode(t, v)), v);
  assertEquals(decode(["address[]", "bytes[]"], encode(["address[]", "bytes[]"], [[ETH, WORTH], ["0x01", "0x"]])), [[ETH, WORTH], ["0x01", "0x"]]);
});

async function ephemeral(): Promise<{ signer: Signer; pub: string }> {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { pub: btoa(String.fromCharCode(...raw)), signer: { keyId: await keyIdOf(raw), sign: async (m) => new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, m as Uint8Array<ArrayBuffer>)) } };
}
Deno.test("proof sign/verify + tamper, wrong key, expiry", async () => {
  const k = await ephemeral(), other = await ephemeral(); const now = Date.UTC(2026, 9, 30);
  const env: any = await signProof({ block_number: 1, sellable: true, buy_tax: 0 }, { token: BRETT }, k.signer, { now });
  assertEquals((await verifyProof(env, k.pub, now)).ok, true);
  assertEquals((await verifyProof(env, other.pub, now)).reason, "key_id_mismatch");
  const t = structuredClone(env); t.claims.sellable = false; assertEquals((await verifyProof(t, k.pub, now)).reason, "bad_signature");
  const t2 = structuredClone(env); t2.subject.token = UR; assertEquals((await verifyProof(t2, k.pub, now)).reason, "bad_signature");
  assertEquals((await verifyProof(env, k.pub, now + 2 * 86400_000)).reason, "expired");
  assertEquals((await verifyProof(env, k.pub, null)).ok, true);
  const t3 = structuredClone(env); t3.spec = "x"; assertEquals((await verifyProof(t3, k.pub, now)).reason, "unsupported_spec");
  const tx: any = await signProof({ verdict: "warn" }, { type: "base_unsigned_tx", to: BRETT }, k.signer, { now });
  assertEquals(tx.subject.type, "base_unsigned_tx"); assertEquals((await verifyProof(tx, k.pub, now)).ok, true);
});

Deno.test("decodeTx: approve / increaseAllowance / permit / permit2 / transfer / transferFrom", () => {
  const a = decodeTx({ to: BRETT, data: call("approve(address,uint256)", [UR, MAX_UINT]) });
  assertEquals(a.method, "approve(address,uint256)"); assertEquals(a.approvals[0], { kind: "erc20_approve", token: BRETT, spender: UR, amount: MAX_UINT.toString(), unlimited: true }); assertEquals(a.tokens, [BRETT]);
  assertEquals(decodeTx({ to: BRETT, data: call("approve(address,uint256)", [UR, 5n]) }).approvals[0].unlimited, false);
  assertEquals(decodeTx({ to: BRETT, data: call("increaseAllowance(address,uint256)", [UR, MAX_UINT]) }).approvals[0].kind, "erc20_increase_allowance");
  const p = decodeTx({ to: BRETT, data: call("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", [ETH, UR, MAX_UINT, 1n, 27n, "0x" + "11".repeat(32), "0x" + "22".repeat(32)]) });
  assertEquals(p.approvals[0].spender, UR); assertEquals(p.approvals[0].kind, "eip2612_permit");
  const p2 = decodeTx({ to: "0x000000000022d473030f116ddee9f6b43ac78ba3", data: call("approve(address,address,uint160,uint48)", [BRETT, UR, (1n << 160n) - 1n, 0n]) });
  assertEquals(p2.approvals[0], { kind: "permit2_approve", token: BRETT, spender: UR, amount: MAX_UINT.toString(), unlimited: true });
  assertEquals(decodeTx({ to: BRETT, data: call("transfer(address,uint256)", [UR, 7n]) }).transfers[0], { token: BRETT, to: UR, amount: "7" });
  assertEquals(decodeTx({ to: BRETT, data: call("transferFrom(address,address,uint256)", [ETH, UR, 7n]) }).transfers[0].to, UR);
  assertEquals(decodeTx({ to: BRETT }).method, "native_transfer");
  const u = decodeTx({ to: BRETT, data: "0xdeadbeef" }); assertEquals(u.method, "unknown"); assert(u.notes[0].includes("not_decoded"));
  assertEquals(decodeTx({ to: BRETT, data: "0x095ea7b3" + "00" }).method, "decode_failed");
});
Deno.test("decodeTx: v2/v3 routers, multicall, Universal Router v2/v3/v4", () => {
  const W = "0x4200000000000000000000000000000000000006";
  const s2 = decodeTx({ to: UR, data: call("swapExactETHForTokens(uint256,address[],address,uint256)", [0n, [W, BRETT], ETH, 1n]) });
  assertEquals(s2.swaps[0], { venue: "v2_router", token_in: ETH, token_out: BRETT });
  const path = "0x" + W.slice(2) + "002710" + BRETT.slice(2); assertEquals(v3Path(path), [W, BRETT]);
  const inner = call("exactInput((bytes,address,uint256,uint256))", [[path, ETH, 1n, 0n]]);
  const m = decodeTx({ to: UR, data: call("multicall(uint256,bytes[])", [1n, [inner]]) });
  assertEquals(m.swaps[0].token_out, BRETT); assertEquals(m.tokens.sort(), [W, BRETT].sort());
  const v4 = "0x" + encode(["bytes", "bytes[]"], ["0x060c0f", ["0x" + encode(["((address,address,uint24,int24,address),bool,uint128,uint128,bytes)"], [[[ETH, WORTH, 0n, 200n, HOOK], true, 1n, 0n, "0x"]]), "0x", "0x"]]);
  const v3in = "0x" + encode(["address", "uint256", "uint256", "bytes", "bool"], [ETH, 1n, 0n, path, false]);
  const v2in = "0x" + encode(["address", "uint256", "uint256", "address[]", "bool"], [ETH, 1n, 0n, [W, BRETT], true]);
  const u = decodeTx({ to: UR, data: call("execute(bytes,bytes[],uint256)", ["0x0b00081005", ["0x", v3in, v2in, v4, "0x"], 9n]) });
  assertEquals(u.swaps.map((s) => s.venue), ["universal_router_v3", "universal_router_v2", "universal_router_v4"]);
  assertEquals(u.swaps[2].pool_key, { currency0: ETH, currency1: WORTH, fee: 0, tick_spacing: 200, hooks: HOOK }); assertEquals(u.swaps[2].token_out, WORTH);
  assert(u.notes.includes("ur_command_WRAP_ETH"));
});

const okSim = (over: Record<string, unknown> = {}, sel: Record<string, unknown> = { version: 3, pool: "0xp", hooks: null }) =>
  ({ selected: sel, simulation: { rpc_error: null, result: { stage: "ok", buy_tax: 0, sell_tax: 0, round_trip_return: 0.97, revert: null, ...over } } });
const F = (p: Partial<Facts>): Facts => ({ tx_sim: null, approvals: [], token_sims: [], ...p });
const codes = (r: { reasons: { code: string }[] }) => r.reasons.map((x) => x.code);
Deno.test("policy thresholds are deterministic", () => {
  assertEquals(evaluate(F({ token_sims: [{ token: BRETT, sim: okSim() }] })).verdict, "allow");
  assertEquals(evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ sell_tax: 0.01 }) }] })).verdict, "allow");
  const w = evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ sell_tax: 0.05 }) }] })); assertEquals(w.verdict, "warn"); assertEquals(w.reasons[0], { code: "sell_tax", token: BRETT, pct: 5 });
  assertEquals(evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ buy_tax: 0.3 }) }] })).verdict, "block");
  assertEquals(evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ buy_tax: 0.299 }) }] })).verdict, "warn");
  const h = evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ stage: "sell_reverted", sell_tax: null, round_trip_return: null }) }] })); assertEquals(h.verdict, "block"); assertEquals(codes(h), ["honeypot"]);
  assertEquals(codes(evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ stage: "sell_zero" }) }] }))), ["honeypot"]);
  const b = evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ stage: "buy_reverted" }) }] })); assertEquals(b.verdict, "warn"); assertEquals(b.unknowns[0].what, "sellability");
  assertEquals(codes(evaluate(F({ token_sims: [{ token: BRETT, sim: okSim({ round_trip_return: 0.5 }) }] }))), ["low_round_trip_return"]);
  const hk = evaluate(F({ token_sims: [{ token: WORTH, sim: okSim({}, { version: 4, pool: "0xid", hooks: HOOK }) }] })); assertEquals(hk.verdict, "warn"); assertEquals(hk.reasons[0].hook, HOOK);
  assertEquals(evaluate(F({ token_sims: [{ token: WORTH, sim: okSim({}, { version: 4, pool: "0xid", hooks: ETH }) }] })).verdict, "allow");
  const np = evaluate(F({ token_sims: [{ token: BRETT, sim: { selected: null, no_pool_reason: "x" }, token_verification: { address: BRETT, source: "sourcify", status: "verified" } }] }));
  assertEquals(np.verdict, "warn"); assertEquals(np.reasons, [{ code: "no_supported_liquidity", token: BRETT, severity: "normal" }]);
  for (const st of ["not_found", "lookup_failed"] as const) {
    const nu = evaluate(F({ token_sims: [{ token: BRETT, sim: { selected: null, no_pool_reason: "x" }, token_verification: { address: BRETT, source: "sourcify", status: st } }] }));
    assertEquals(nu.verdict, "warn"); assertEquals(nu.reasons, [{ code: "no_supported_liquidity_unverified_token", token: BRETT, severity: "high", verification: st }]);
  }
  assertEquals(evaluate(F({ token_sims: [{ token: BRETT, sim: null, error: "boom" }] })).verdict, "warn");
  const rv = evaluate(F({ tx_sim: { reverted: true, revert_data: "0x", message: "empty_revert" } })); assertEquals(rv.verdict, "block"); assertEquals(rv.reasons[0], { code: "tx_reverts", data: "0x", message: "empty_revert" });
  assertEquals(evaluate(F({ tx_sim: { reverted: false, rpc_error: "429" } })).verdict, "warn");
});
Deno.test("policy: approvals", () => {
  const base = { kind: "erc20_approve", token: BRETT, amount: MAX_UINT.toString(), unlimited: true };
  const A = (x: Record<string, unknown>) => evaluate(F({ approvals: [{ ...base, spender: "0xs", spender_known: null, spender_is_contract: true, spender_verification: null, ...x } as any] }));
  assertEquals(A({ spender_known: "uniswap_universal_router_v4" }).verdict, "allow");
  assertEquals(codes(A({ spender_is_contract: false })), ["approval_eoa_spender"]);
  const vv = A({ spender_verification: { address: "0xs", source: "sourcify", status: "verified" } }); assertEquals(vv.verdict, "warn"); assertEquals(codes(vv), ["approval_unknown_verified_spender"]);
  const u = A({ spender_verification: { address: "0xs", source: "sourcify", status: "not_found" } }); assertEquals(u.verdict, "warn"); assertEquals(u.reasons[0].verification, "not_found");
  const lf = A({ spender_verification: { address: "0xs", source: "sourcify", status: "lookup_failed" } }); assertEquals(lf.unknowns[0].what, "spender_verification");
  assertEquals(A({ amount: "0", unlimited: false, spender_is_contract: false }).verdict, "allow"); // revocation
  const small = A({ amount: "1000", unlimited: false, spender_is_contract: false, token_total_supply: (10n ** 27n).toString() });
  assertEquals(small.verdict, "warn"); assertEquals(small.reasons[0].severity, "normal");
  const capped = A({ amount: "500", unlimited: false, spender_is_contract: false, token_total_supply: "500" }); assertEquals(capped.reasons[0].severity, "high"); // >= totalSupply
});
Deno.test("tx sim overrides only top up when needed", () => {
  assertEquals(txSimOverrides({ to: BRETT, from: UR, value: "0" }, 10n ** 18n), {});
  assertEquals(txSimOverrides({ to: BRETT, from: UR, value: 10n ** 15n }, 0n), { [UR]: { balance: "0x" + (10n ** 15n + 10n ** 18n).toString(16) } });
});
Deno.test("presign with stub rpc: max approve to unverified contract -> warn; reverting tx -> block", async () => {
  const spender = "0x1111111111111111111111111111111111111111";
  const rpc = async (m: string, p: any[]) => {
    if (m === "eth_getBalance") return "0x0"; if (m === "eth_getCode") return "0x6000"; if (m === "eth_getTransactionCount") return "0x1";
    if (m === "eth_getBlockByNumber") return { hash: "0x" + "ab".repeat(32) };
    if (m === "eth_call") { if (p[0].data.startsWith("0xa9059cbb")) throw new Error("execution reverted data=0x"); return "0x" + word(1); }
    throw new Error("unexpected " + m);
  };
  const lookup = async (a: string) => ({ address: a, source: "sourcify", status: "not_found" as const, http: 404 });
  const r = await presign(rpc, { tx: { to: BRETT, from: UR, data: call("approve(address,uint256)", [spender, MAX_UINT]) } }, 100, { lookup, skipTokens: [BRETT] });
  assertEquals(r.verdict, "warn"); assertEquals(r.reasons[0].code, "approval_unverified_spender"); assertEquals(r.reasons[0].severity, "high"); assertEquals(r.block_hash, "0x" + "ab".repeat(32)); assertEquals(r.tx_simulation.reverted, false);
  const t = await presign(rpc, { tx: { to: BRETT, from: UR, data: call("transfer(address,uint256)", [spender, 1n]) } }, 100, { lookup, skipTokens: [BRETT] });
  assertEquals(t.verdict, "block"); assertEquals(t.reasons[0].code, "tx_reverts");
});

// Regression: TRUMP (R3) has two v3 WETH pools whose in-range liquidity is 0 at block 53273610.
// v0.1 dropped them with the quote_depth_eth > 0 filter and reported "no pool".
Deno.test("regression: zero in-range liquidity v3 pools are still simulated (TRUMP/WETH 500 + 10000)", () => {
  const W = "0x4200000000000000000000000000000000000006";
  const p500 = { version: 3, pool: "0xed3ac538bbb824bf3c8ea9d1075b965d233e96b2", quote: W, fee: 500, liquidity_raw: "0", sqrt_price_x96: "4295128740", quote_depth_raw: "0", quote_depth_eth: 0, quote_balance_raw: "907083172003688", spot_token_per_quote: null, lp_fee_ppm: 500, source: "v3_factory.getPool" } as any;
  const p10k = { ...p500, pool: "0xd641c602cc11dac140d0bcbf741e42201bf5b03a", fee: 10000, sqrt_price_x96: "142651284308418067891098769", quote_balance_raw: "3", lp_fee_ppm: 10000 };
  const r = selectUsable([p10k, p500]);
  assertEquals(r.mode, "zero_active_liquidity_fallback"); assertEquals(r.usable.map((x) => x.fee), [500, 10000]);
  const live = { ...p500, pool: "0xaaaa", quote_depth_eth: 1 };
  assertEquals(selectUsable([p500, live, p10k]), { usable: [live], mode: "active_liquidity" });
  assertEquals(selectUsable([]).mode, "none");
});
Deno.test("regression: empty factory response is an rpc error, not 'no pool'", () => {
  assertThrows(() => factoryAddr("0x")); assertThrows(() => factoryAddr(null)); assertThrows(() => factoryAddr(""));
  assertEquals(factoryAddr("0x" + "0".repeat(64)), "0x0000000000000000000000000000000000000000");
  assertEquals(factoryAddr("0x" + "0".repeat(24) + "ed3ac538bbb824bf3c8ea9d1075b965d233e96b2"), "0xed3ac538bbb824bf3c8ea9d1075b965d233e96b2");
});

// M1 regression: finite but huge grants to unknown spenders must not be "allow" (b6f186e returned allow).
Deno.test("M1: finite huge approvals via approve / increaseAllowance / permit to an unknown EOA -> warn high", async () => {
  const EOA = "0x1111111111111111111111111111111111111111", USDC_ = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
  const rpc = async (m: string, p: any[]) => {
    if (m === "eth_getBlockByNumber") return { hash: "0x" + "cd".repeat(32) }; if (m === "eth_getBalance") return "0x" + (10n ** 18n).toString(16);
    if (m === "eth_getCode") return "0x"; if (m === "eth_getTransactionCount") return "0x0";
    if (m === "eth_call") return "0x" + word(10n ** 16n); // tx result / totalSupply = 1e16 (10B USDC)
    throw new Error("unexpected " + m);
  };
  const lookup = async (a: string) => ({ address: a, source: "sourcify", status: "not_found" as const, http: 404 });
  const amts = [1n << 254n, 10n ** 30n, (1n << 128n) - 1n];
  const mk = (amt: bigint) => [
    call("approve(address,uint256)", [EOA, amt]),
    call("increaseAllowance(address,uint256)", [EOA, amt]),
    call("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", [UR, EOA, amt, 9999999999n, 27n, "0x" + "11".repeat(32), "0x" + "22".repeat(32)]),
  ];
  for (const amt of amts) for (const data of mk(amt)) {
    const r = await presign(rpc, { tx: { to: USDC_, from: UR, data } }, 100, { lookup });
    assertEquals(r.verdict, "warn", `${data.slice(0, 10)} ${amt}`);
    const x = r.reasons.find((q: any) => q.code === "approval_eoa_spender") as any; assert(x, "missing reason"); assertEquals(x.severity, "high"); assertEquals(x.large, true);
  }
});
Deno.test("L2: presign proof subject carries input_sha256; block_hash required", async () => {
  const signer = { keyId: "k", sign: async () => new Uint8Array(64) };
  const claims: any = { block_hash: "0x" + "ab".repeat(32), input: { token: BRETT } };
  const p: any = await signPresign(claims, signer as any);
  assertEquals(p.subject.input_sha256.length, 64); assertEquals(p.subject.type, "base_token");
  let threw = false; try { await signPresign({ input: { token: BRETT } }, signer as any); } catch { threw = true; } assert(threw);
});
Deno.test("L3: native transfer / ERC20 transfer to fresh EOA -> warn transfer_to_fresh_eoa", () => {
  const r = evaluate(F({ fresh_recipients: [{ to: "0x1", token: ETH, amount: "1", kind: "native_transfer" }] }));
  assertEquals(r.verdict, "warn"); assertEquals(codes(r), ["transfer_to_fresh_eoa"]);
});
Deno.test("L4: rpc method allow-list, response cap, budget", async () => {
  const stat: any = { calls: 0, errors: {}, fallbacks: 0 };
  const ok = (body: string) => (async () => new Response(body)) as unknown as typeof fetch;
  const r1 = makeFallbackRpc(["http://x"], stat, { fetchFn: ok('{"result":"0x1"}') });
  let e = ""; try { await r1("eth_sendRawTransaction", ["0x"]); } catch (x) { e = (x as Error).message; } assert(e.startsWith("method_not_allowed"));
  e = ""; try { await r1("eth_sign", []); } catch (x) { e = (x as Error).message; } assert(e.startsWith("method_not_allowed"));
  assertEquals(await r1("eth_chainId", []), "0x1");
  const big = makeFallbackRpc(["http://x"], { calls: 0, errors: {}, fallbacks: 0 }, { maxBytes: 10, fetchFn: ok('{"result":"0x' + "0".repeat(100) + '"}') });
  e = ""; try { await big("eth_call", []); } catch (x) { e = (x as Error).message; } assertEquals(e, "response_too_large");
  const st2: any = { calls: 0, errors: {}, fallbacks: 0 }; const b = makeFallbackRpc(["http://x"], st2, { budget: 2, fetchFn: ok('{"result":"0x1"}') });
  await b("eth_chainId", []); await b("eth_chainId", []); e = ""; try { await b("eth_chainId", []); } catch (x) { e = (x as Error).message; } assertEquals(e, "rpc_budget_exceeded");
  assertEquals(await readCapped(new Response("abc"), 3), "abc");
});

// 0.2.1: an allow-looking round trip on a fallback (zero in-range liquidity) pool must not stay allow
Deno.test("fallback pool mode adds thin_or_out_of_range_liquidity (warn) with pool and quote balance", () => {
  const sel = { version: 3, pool: "0xed3ac538", quote: "0x4200000000000000000000000000000000000006", hooks: null, quote_balance_raw: "907000000000000" };
  const fb = { ...okSim({ round_trip_return: 0.95 }, sel), pool_mode: "zero_active_liquidity_fallback" };
  const r = evaluate(F({ token_sims: [{ token: BRETT, sim: fb as never }] }));
  assertEquals(r.verdict, "warn");
  assertEquals(r.reasons, [{ code: "thin_or_out_of_range_liquidity", token: BRETT, pool: "0xed3ac538", version: 3, quote: sel.quote, quote_balance_raw: "907000000000000", severity: "normal" }]);
  assertEquals(evaluate(F({ token_sims: [{ token: BRETT, sim: { ...okSim({}, sel), pool_mode: "active_liquidity" } as never }] })).verdict, "allow");
  const hp = evaluate(F({ token_sims: [{ token: BRETT, sim: { ...okSim({ stage: "sell_reverted" }, sel), pool_mode: "zero_active_liquidity_fallback" } as never }] }));
  assertEquals(hp.verdict, "block"); assertEquals(codes(hp), ["thin_or_out_of_range_liquidity", "honeypot"]);
});
