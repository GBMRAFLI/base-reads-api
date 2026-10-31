// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.26;

// Read-only simulation helper. It is NEVER deployed: it is injected with an eth_call code override at a synthetic
// address, funded with a balance override, and runs one buy then one sell against a single pool inside that eth_call.
// kind: 2 = Uniswap v2 pair, 3 = Uniswap v3 pool, 4 = Uniswap v4 PoolManager (pool = manager, key fields below).
// quote: the asset paid in (address(0) = native ETH, only for v4; WETH is wrapped from the ETH balance; any other
// ERC-20 quote must be funded by a storage override).

interface IERC20 { function balanceOf(address) external view returns (uint256); function transfer(address, uint256) external returns (bool); }
interface IWETH { function deposit() external payable; }
interface IV2Pair { function token0() external view returns (address); function getReserves() external view returns (uint112, uint112, uint32);
  function swap(uint256, uint256, address, bytes calldata) external; }
interface IV3Pool { function swap(address, bool, int256, uint160, bytes calldata) external returns (int256, int256); }
struct PoolKey { address currency0; address currency1; uint24 fee; int24 tickSpacing; address hooks; }
struct SwapParams { bool zeroForOne; int256 amountSpecified; uint160 sqrtPriceLimitX96; }
interface IPoolManager {
  function unlock(bytes calldata) external returns (bytes memory);
  function swap(PoolKey memory, SwapParams memory, bytes calldata) external returns (int256);
  function sync(address) external;
  function settle() external payable returns (uint256);
  function take(address, address, uint256) external;
}

contract SellSimHelper {
  address constant WETH = 0x4200000000000000000000000000000000000006;
  uint160 constant MIN_P = 4295128740; uint160 constant MAX_P = 1461446703485210103287273052203988822378723970341;
  struct Job { uint8 kind; address pool; address quote; address token; uint24 fee; int24 tickSpacing; address hooks; uint256 amountIn; }
  Job job; address active;

  receive() external payable {}

  // r[0] buyIn, r[1] buyPoolOut, r[2] buyReceived, r[3] sellSent, r[4] sellPoolIn, r[5] sellPoolOut, r[6] sellReceived,
  // r[7] buyGas, r[8] sellGas. stage: 0 ok, 1 buy reverted, 2 sell reverted, 3 sell returned zero.
  function run(Job calldata j) external returns (uint8 stage, bytes memory err, uint256[9] memory r) {
    job = j;
    if (j.quote == WETH) IWETH(WETH).deposit{value: j.amountIn}();
    uint256 g = gasleft();
    (bool ok, bytes memory ret) = address(this).call(abi.encodeWithSelector(this.leg.selector, true, j.amountIn));
    r[7] = g - gasleft();
    if (!ok) return (1, ret, r);
    (r[0], r[1], r[2]) = abi.decode(ret, (uint256, uint256, uint256));
    if (r[2] == 0) return (1, bytes("zero_received"), r);
    g = gasleft();
    (ok, ret) = address(this).call(abi.encodeWithSelector(this.leg.selector, false, r[2]));
    r[8] = g - gasleft();
    if (!ok) { r[3] = r[2]; return (2, ret, r); }
    (r[3], r[4], r[5], r[6]) = abi.decode(ret, (uint256, uint256, uint256, uint256));
    return (r[6] == 0 ? 3 : 0, "", r);
  }

  function bal(address a, address who) internal view returns (uint256) { return a == address(0) ? who.balance : IERC20(a).balanceOf(who); }

  // buy: quote -> token (returns in, poolOut, received). sell: token -> quote (returns sent, poolIn, poolOut, received).
  function leg(bool buy, uint256 amt) external returns (uint256, uint256, uint256, uint256) {
    require(msg.sender == address(this), "self");
    Job memory j = job;
    address tin = buy ? j.quote : j.token; address tout = buy ? j.token : j.quote;
    uint256 before = bal(tout, address(this)); uint256 poolIn = amt; uint256 poolOut;
    if (j.kind == 2) (poolIn, poolOut) = v2(j.pool, tin, tout, amt);
    else if (j.kind == 3) (poolIn, poolOut) = v3(j.pool, tin, tout, amt);
    else if (j.kind == 4) { bytes memory o = IPoolManager(j.pool).unlock(abi.encode(tin, tout, amt)); (poolIn, poolOut) = abi.decode(o, (uint256, uint256)); }
    else revert("kind");
    uint256 got = bal(tout, address(this)) - before;
    if (buy) { require(got > 0 || poolOut == 0, "no_tokens_received"); return (amt, poolOut, got, 0); }
    return (amt, poolIn, poolOut, got);
  }

  function v2(address pair, address tin, address tout, uint256 amt) internal returns (uint256 poolIn, uint256 out) {
    bool inIs0 = IV2Pair(pair).token0() == tin;
    (uint112 r0, uint112 r1,) = IV2Pair(pair).getReserves();
    uint256 pb = IERC20(tin).balanceOf(pair);
    require(IERC20(tin).transfer(pair, amt), "transfer_in_false");
    poolIn = IERC20(tin).balanceOf(pair) - pb;
    (uint256 rin, uint256 rout) = inIs0 ? (uint256(r0), uint256(r1)) : (uint256(r1), uint256(r0));
    out = poolIn * 997 * rout / (rin * 1000 + poolIn * 997);
    IV2Pair(pair).swap(inIs0 ? 0 : out, inIs0 ? out : 0, address(this), "");
    tout;
  }

  function v3(address pool, address tin, address tout, uint256 amt) internal returns (uint256, uint256) {
    bool z = tin < tout; active = pool;
    (int256 a0, int256 a1) = IV3Pool(pool).swap(address(this), z, int256(amt), z ? MIN_P : MAX_P, abi.encode(tin));
    active = address(0);
    return z ? (uint256(a0), uint256(-a1)) : (uint256(a1), uint256(-a0));
  }
  function uniswapV3SwapCallback(int256 a0, int256 a1, bytes calldata d) external {
    require(msg.sender == active, "cb");
    address tin = abi.decode(d, (address));
    uint256 owe = uint256(a0 > 0 ? a0 : a1);
    require(IERC20(tin).transfer(msg.sender, owe), "transfer_in_false");
  }

  function unlockCallback(bytes calldata d) external returns (bytes memory) {
    Job memory j = job; require(msg.sender == j.pool, "cb");
    (address tin, address tout, uint256 amt) = abi.decode(d, (address, address, uint256));
    PoolKey memory k = PoolKey(j.quote < j.token ? j.quote : j.token, j.quote < j.token ? j.token : j.quote, j.fee, j.tickSpacing, j.hooks);
    bool z = tin == k.currency0;
    int256 delta = IPoolManager(j.pool).swap(k, SwapParams(z, -int256(amt), z ? MIN_P : MAX_P), "");
    int128 d0 = int128(delta >> 128); int128 d1 = int128(delta);
    int128 din = z ? d0 : d1; int128 dout = z ? d1 : d0;
    uint256 owe = din < 0 ? uint256(int256(-din)) : 0; uint256 out = dout > 0 ? uint256(int256(dout)) : 0;
    uint256 paid;
    if (owe > 0) {
      if (tin == address(0)) paid = IPoolManager(j.pool).settle{value: owe}();
      else { IPoolManager(j.pool).sync(tin); require(IERC20(tin).transfer(j.pool, owe), "transfer_in_false"); paid = IPoolManager(j.pool).settle(); }
    }
    if (out > 0) IPoolManager(j.pool).take(tout, address(this), out);
    return abi.encode(paid, out);
  }
}
