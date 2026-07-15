import { wrapFetchWithPayment } from "@x402/fetch";
import { privateKeyToAccount } from "viem/accounts";
import { Hex } from "viem";
import { settleResponseFromHeader } from "@x402/core/http";

/**
 * x402 v2 Payment Client for Alerts API
 * 
 * This module handles the x402 v2 payment protocol for creating paid price alerts.
 * Uses the @x402/fetch package for automatic payment challenge handling.
 * 
 * Migration notes:
 * - Uses canonical X-PAYMENT and X-PAYMENT-RESPONSE headers (v2 spec)
 * - settleResponseFromHeader imported from @x402/core/http
 */

const PRIVATE_KEY = process.env.AGENT_WALLET_PRIVATE_KEY as Hex;
if (!PRIVATE_KEY) {
  throw new Error("AGENT_WALLET_PRIVATE_KEY environment variable is required");
}

const account = privateKeyToAccount(PRIVATE_KEY);

const fetchWithPayment = wrapFetchWithPayment(fetch, account);

const PORT = Number(process.env.PORT ?? 3000);
const ALERTS_API_URL = `http://localhost:${PORT}/alerts`;

export interface PriceAlertPayload {
  asset: string;
  condition: "gt" | "lt" | "gte" | "lte";
  targetPriceUsd: number;
  payer?: string;
}

export interface PriceAlertResponse {
  alert: {
    id: string;
    payer: string;
    asset: string;
    condition: string;
    targetPriceUsd: number;
    createdAt: number;
  };
  paymentMeta: string | null;
  transactionHash: string | undefined;
}

export async function createPaidPriceAlert(payload: PriceAlertPayload): Promise<PriceAlertResponse> {
  console.log("\n  [x402 v2 Handshake]");
  console.log("    Step 1: Client → Server: Initial request (no payment)");

  const res = await fetchWithPayment(ALERTS_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const paymentResponseHeader = res.headers.get("x-payment-response");
  let settlement = null;

  if (paymentResponseHeader) {
    try {
      settlement = settleResponseFromHeader(paymentResponseHeader);
    } catch (error) {
      // Failed to decode settlement
    }
  }

  if (res.status === 200) {
    console.log("    Step 2: Client processed 402 challenge, created payment authorization");
    console.log("    Step 3: Client → Server: Retry with X-PAYMENT ($0.01 USDC)");
    if (settlement?.transaction) {
      console.log(`    Step 4: Payment settled on-chain: ${settlement.transaction}`);
    }
  }

  if (!res.ok) {
    const errorBody = await res.text().catch(() => "");
    const errorMessage = errorBody ? `: ${errorBody}` : "";
    throw new Error(`Alerts API error (${res.status} ${res.statusText})${errorMessage}`);
  }

  const data = await res.json();

  if (!data.alert) {
    throw new Error("Invalid response from alerts API: missing alert data");
  }

  return {
    alert: data.alert,
    paymentMeta: paymentResponseHeader,
    transactionHash: settlement?.transaction
  };
}
