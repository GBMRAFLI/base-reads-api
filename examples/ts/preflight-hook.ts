// Pre-pay Check hook for the official x402 TypeScript client (@x402/core).
// Before any payment is created, fetch signed facts about the target and abort on hard failures.
// The preflight call itself costs $0.001 and is paid by a SEPARATE client (no hook recursion).
import { x402Client } from "@x402/core";

const MAX_LATENCY_MS = 3000;

export function withPrepayCheck(client: x402Client, preflightFetch: typeof fetch, resourceUrl: () => string,
  preflightBase = "https://<your-deploy-host>/x402/preflight?url=") {
  client.onBeforePaymentCreation(async (ctx) => {
    const res = await preflightFetch(preflightBase + encodeURIComponent(resourceUrl()));
    if (!res.ok) return { abort: true, reason: `preflight unavailable (${res.status})` };
    const { facts } = await res.json(); // verify facts.signature with the published Ed25519 key if you need provenance
    const req = ctx.selectedRequirements;
    if (!facts.challenge.valid) return { abort: true, reason: "challenge invalid: " + facts.challenge.problems.join(",") };
    if (!facts.challenge.accepts.some((a: any) => a.payTo?.toLowerCase() === req.payTo.toLowerCase()))
      return { abort: true, reason: "payTo differs from the challenge observed by preflight" };
    if (facts.reachability.latency_ms > MAX_LATENCY_MS) return { abort: true, reason: "slow endpoint" };
    const reuse = facts.bazaar?.payout_wallet_reuse?.[req.payTo.toLowerCase()];
    if (reuse && reuse.hosts_using_wallet > 20) return { abort: true, reason: "payout wallet shared by many hosts" };
    // thresholds are YOUR policy; the service only reports facts
  });
  return client;
}
