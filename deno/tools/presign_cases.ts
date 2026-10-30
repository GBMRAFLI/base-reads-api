// Builds the synthetic UNSIGNED tx test set (never signed or sent; used only for eth_call).
// Usage (from deno/): deno run -A tools/presign_cases.ts <token list file> > cases.json
import { call, encode } from "../lib/abi.ts";
import { MAX_UINT } from "../lib/presign.ts";
const T = { BRETT: "0x532f27101965dd16442e59d40670faf5ebb142e4", DEGEN: "0x4ed4e862860bed51a9570b96d89af5e1b0efefed", OLIVIA: "0x106bb22a0a2304bdb84a906bb9e63f20607cf2ba",
  POD: "0xed664536023d8e4b1640c394777d34abaff1df8f", WORTH: "0xb200000000000000000000585fd80c20af698f01", WETH: "0x4200000000000000000000000000000000000006", USDC: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" };
const UR = "0x6ff5693b99212da76ad316178a184ab56d299b43", V2R = "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24", SR02 = "0x2626664c2603336e57b271c5c0b26f421741e481";
const FROM = "0x00000000000000000000000000000000000a11ce"; // arbitrary address, no code
const EOA = "0x00000000000000000000000000000000000b0b01";  // arbitrary address, no code
const BRETT_POOL = "0xba3f945812a83471d709bce9c3ca699a19fb46f7"; // holds BRETT; used as `from` for a funded transfer
const DL = 4_102_444_800n; const IN = 10n ** 15n; const ETHA = "0x0000000000000000000000000000000000000000";
const hx = (n: number) => n.toString(16).padStart(2, "0");
const v3path = (...p: (string | number)[]) => "0x" + p.map((x) => typeof x === "number" ? x.toString(16).padStart(6, "0") : x.slice(2)).join("");
const urExec = (cmds: number[], inputs: string[]) => call("execute(bytes,bytes[],uint256)", ["0x" + cmds.map(hx).join(""), inputs, DL]);
const v4single = (c1: string, fee: number, ts: number, hooks: string) => {
  const actions = "0x" + [0x06, 0x0c, 0x0f].map(hx).join("");
  const params = ["0x" + encode(["((address,address,uint24,int24,address),bool,uint128,uint128,bytes)"], [[[ETHA, c1, fee, ts, hooks], true, IN, 0n, "0x"]]),
    "0x" + encode(["address", "uint256"], [ETHA, IN]), "0x" + encode(["address", "uint256"], [c1, 0n])];
  return urExec([0x10], ["0x" + encode(["bytes", "bytes[]"], [actions, params])]);
};
const cases: any[] = [];
const list = Deno.args[0];
if (list) for (const l of (await Deno.readTextFile(list)).split("\n")) { const [label, , address] = l.trim().split(/\s+/); if (address) cases.push({ label, input: { token: address } }); }
const tx = (label: string, to: string, data: string, value = 0n, from = FROM) => cases.push({ label, input: { tx: { from, to, data, value: value.toString() } } });
tx("tx_approve_max_known_router", T.BRETT, call("approve(address,uint256)", [UR, MAX_UINT]));
tx("tx_approve_max_eoa", T.BRETT, call("approve(address,uint256)", [EOA, MAX_UINT]));
tx("tx_approve_max_unverified_contract", T.BRETT, call("approve(address,uint256)", [T.OLIVIA, MAX_UINT]));
tx("tx_approve_max_verified_unlisted_contract", T.BRETT, call("approve(address,uint256)", ["0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43", MAX_UINT]));
tx("tx_approve_small_eoa", T.BRETT, call("approve(address,uint256)", [EOA, 10n ** 18n]));
tx("tx_transfer_funded", T.BRETT, call("transfer(address,uint256)", [EOA, 10n ** 18n]), 0n, BRETT_POOL);
tx("tx_transfer_unfunded", T.BRETT, call("transfer(address,uint256)", [EOA, 10n ** 18n]));
tx("tx_v2_router_buy_honeypot_path", V2R, call("swapExactETHForTokens(uint256,address[],address,uint256)", [0n, [T.WETH, T.USDC, T.OLIVIA], FROM, DL]), IN);
tx("tx_swaprouter02_exact_input_single", SR02, call("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))", [[T.WETH, T.BRETT, 10000, FROM, IN, 0n, 0n]]), IN);
tx("tx_ur_wrap_v3_swap", UR, urExec([0x0b, 0x00], ["0x" + encode(["address", "uint256"], ["0x0000000000000000000000000000000000000002", IN]),
  "0x" + encode(["address", "uint256", "uint256", "bytes", "bool"], [FROM, IN, 0n, v3path(T.WETH, 3000, T.DEGEN), false])]), IN);
tx("tx_ur_v4_swap_hookless", UR, v4single(T.POD, 10000, 200, ETHA), IN);
tx("tx_ur_v4_swap_hooked", UR, v4single(T.WORTH, 0, 200, "0x985c14baa2a18316ffda0aefb3a632fadfca2acc"), IN);
tx("tx_unknown_selector", T.BRETT, "0xdeadbeef");
// 0.2 additions (audit M1 / L3)
tx("tx_approve_2pow254_eoa_usdc", T.USDC, call("approve(address,uint256)", [EOA, 1n << 254n]));
tx("tx_increase_allowance_1e30_eoa", T.BRETT, call("increaseAllowance(address,uint256)", [EOA, 10n ** 30n]));
tx("tx_native_transfer_fresh_eoa", EOA, "0x", IN);
console.log(JSON.stringify(cases, null, 1));
