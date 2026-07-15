import dotenv from "dotenv";
import path from "path";

// Load .env from project root
const projectRoot = path.resolve(__dirname, "../..");
dotenv.config({ path: path.join(projectRoot, ".env"), override: true });

import express from "express";
import cors from "cors";
import { createHash } from "node:crypto";
import { paymentMiddleware } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { decodePaymentHeader, settleResponseFromHeader } from "@x402/core/http";
import OpenAI from "openai";
import { createPaidPriceAlert } from "./x402Client";
import { startChatInterface } from "./chat";

/**
 * Unified API Server
 *
 * This server demonstrates a crypto price alert system that combines:
 * - Natural language processing (via Gemini AI)
 * - x402 payment protocol for micropayments (v2)
 * - Chainlink CRE (Chainlink Runtime Environment) for on-chain operations
 *
 * Architecture:
 * - /chat: Natural language interface for creating alerts (no payment required)
 *   - Uses Gemini AI to extract alert parameters from user messages
 *   - Validates that only supported assets (BTC, ETH, LINK) are requested
 *   - Internally calls /alerts endpoint with x402 payment
 *
 * - /alerts: Direct alert creation endpoint (requires x402 payment)
 *   - Protected by x402 v2 payment middleware ($0.01 USDC)
 *   - Creates alert with deterministic ID (SHA256 hash)
 *   - Outputs CRE workflow payload for on-chain storage
 *
 * x402 v2 Payment Flow:
 * 1. Client sends request without payment → Server responds with 402 Payment Required
 * 2. Client processes challenge, creates payment authorization
 * 3. Client retries with X-PAYMENT header → Server validates payment
 * 4. Server creates alert and responds with 200 + settlement transaction hash
 *
 * @see https://x402.org/ - x402 payment protocol documentation
 * @see https://docs.chain.link/cre - Chainlink CRE documentation
 */

const app = express();
app.use(cors());
app.use(express.json());

// ============================================================================
// Configuration & Validation
// ============================================================================

/**
 * Validate required environment variables on startup
 */
if (!process.env.GEMINI_API_KEY) {
  throw new Error("GEMINI_API_KEY environment variable is required");
}
if (!process.env.X402_RECEIVER_ADDRESS) {
  throw new Error("X402_RECEIVER_ADDRESS environment variable is required");
}

/**
 * Gemini client for natural language processing
 * Uses OpenAI SDK with Gemini's OpenAI compatibility endpoint
 */
const llmClient = new OpenAI({
  apiKey: process.env.GEMINI_API_KEY,
  baseURL: "https://generativelanguage.googleapis.com/v1beta/openai/",
});

/**
 * Server port (default: 3000)
 */
const PORT = Number(process.env.PORT ?? 3000);

/**
 * x402 v2 configuration
 * - payTo: recipient address for EVM payments
 * - facilitator: x402 facilitator for settlement
 * - network: CAIP-2 chain ID for Base Sepolia
 */
const payToAddress = process.env.X402_RECEIVER_ADDRESS as `0x${string}`;
const facilitatorUrl = (process.env.X402_FACILITATOR_URL ?? "https://x402.org/facilitator") as `${string}://${string}`;
const NETWORK = "eip155:84532";

/**
 * Supported cryptocurrency assets for price alerts
 * Only BTC, ETH, and LINK are supported in this demo
 */
const ALLOWED_ASSETS = ["BTC", "ETH", "LINK"] as const;

/**
 * Supported price alert conditions
 * - gt: greater than
 * - lt: less than
 * - gte: greater than or equal
 * - lte: less than or equal
 */
const ALLOWED_CONDITIONS = ["gt", "lt", "gte", "lte"] as const;

console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
console.log("Unified API Server (x402 v2)");
console.log(`   Port: ${PORT} | Payment: $0.01 USDC | Network: ${NETWORK}`);
console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

// ============================================================================
// x402 v2 Payment Middleware
// ============================================================================

/**
 * x402 v2 Payment Middleware Configuration
 *
 * Uses the @x402/express package with the Exact EVM scheme.
 * Intercepts requests to protected endpoints and handles the v2 payment flow:
 * - Responds with 402 Payment Required if no valid X-PAYMENT header
 * - Validates payment, processes settlement
 * - Adds X-PAYMENT-RESPONSE header with settlement details
 * 
 * Migration notes:
 * - Uses CAIP-2 chain ID (eip155:84532) instead of human network name (base-sepolia)
 * - Payment header is X-PAYMENT (canonical, per RFC 6648)
 * - Amounts are strings (atomic units) per v2 spec
 */
const x402Scheme = new ExactEvmScheme({
  receiverAddress: payToAddress,
  facilitatorUrl,
});

app.use(
  paymentMiddleware({
    schemes: [x402Scheme],
    routes: {
      "POST /alerts": {
        price: "$0.01",
        network: NETWORK,
        config: {
          description: "Create a crypto price alert",
        },
      },
    },
  })
);

// ============================================================================
// /.well-known/x402 — x402 v2 Discovery Endpoint
// ============================================================================

app.get("/.well-known/x402", (_req, res) => {
  res.json({
    version: "v2",
    resources: ["POST /alerts"],
    resourceDetails: [
      {
        url: "/alerts",
        method: "POST",
        description: "Create a crypto price alert ($0.01 USDC)",
        mimeType: "application/json",
        serviceName: "CRE Price Alerts",
        tags: ["chainlink", "price-alerts", "crypto"],
        pricing: {
          price: "$0.01",
          network: NETWORK,
        },
      },
    ],
    baseGateway: `http://localhost:${PORT}`,
    facilitator: {
      url: facilitatorUrl,
    },
    instructions: "Send a POST /alerts request. If you receive a 402 response, process the X-PAYMENT challenge and retry with the signed authorization.",
  });
});

// ============================================================================
// Health Check
// ============================================================================

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    version: "2.0.0",
    payment: {
      protocol: "x402-v2",
      network: NETWORK,
      price: "$0.01 USDC",
    },
  });
});

// ============================================================================
// Request Logging Middleware
// ============================================================================

/**
 * Request Logging Middleware
 *
 * Logs the x402 v2 payment handshake steps for developer transparency.
 * Uses canonical header names (X-PAYMENT, X-PAYMENT-RESPONSE) per v2 spec.
 */
app.use((req, res, next) => {
  const paymentHeader = req.headers["x-payment"] as string | undefined;
  const hasPayment = !!paymentHeader;

  // Intercept response to log x402 handshake details
  const originalSend = res.send.bind(res);
  res.send = (body: any) => {
    // x402 v2 Handshake Step 1: Server sends 402 Payment Required
    if (res.statusCode === 402 && req.path === "/alerts") {
      console.log("\n  [x402 v2 Handshake]");
      console.log("    Step 1: Server → Client: 402 Payment Required");
      console.log("    Step 2: Client will process challenge and retry with X-PAYMENT header");
    }

    // x402 v2 Handshake Step 3: Server receives payment and validates
    if (hasPayment && req.path === "/alerts") {
      try {
        const decoded = decodePaymentHeader(paymentHeader);
        if ("authorization" in decoded) {
          const auth = decoded.authorization;
          const amountUsd = Number(auth.value) / 10 ** 6;
          console.log("\n  [x402 v2 Handshake]");
          console.log("    Step 3: Client → Server: Payment authorization received");
          console.log(`    - Amount: $${amountUsd.toFixed(2)} USDC`);
          console.log(`    - Payer: ${auth.from}`);
          console.log("    - Validating payment...");
        }
      } catch (e) {
        // Failed to decode payment header
      }
    }

    // x402 v2 Handshake Step 4: Server responds with settlement
    const paymentResponse = res.getHeader("x-payment-response") as string | undefined;
    if (paymentResponse && res.statusCode === 200) {
      try {
        const settlement = settleResponseFromHeader(paymentResponse);
        if (settlement.transaction) {
          console.log("    Step 4: Server → Client: Payment settled on-chain");
          console.log(`    - Transaction: ${settlement.transaction}`);
        }
      } catch (e) {
        // Failed to decode settlement response
      }
    }

    return originalSend(body);
  };

  next();
});

// ============================================================================
// Type Definitions
// ============================================================================

type AlertCondition = "gt" | "lt" | "gte" | "lte";

interface AlertRequestBody {
  asset: string;
  condition: AlertCondition;
  targetPriceUsd: number;
}

interface StoredAlert extends AlertRequestBody {
  id: string;
  payer: string;
  createdAt: number;
}

// ============================================================================
// API Endpoints
// ============================================================================

/**
 * POST /chat
 * Natural language interface for creating price alerts
 */
app.post("/chat", async (req, res) => {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("POST /chat");
  console.log(`  Message: "${req.body.message}"`);

  const { message } = req.body;

  if (!message || typeof message !== "string") {
    console.log("  [ERROR] Invalid message");
    return res.status(400).json({ error: "Missing or invalid message" });
  }

  try {
    console.log("  [1] Extracting alert parameters with Gemini...");
    const response = await llmClient.chat.completions.create({
      model: "gemini-2.0-flash-lite",
      messages: [
        {
          role: "system",
          content: `You are a helpful assistant that creates crypto price alerts. 

IMPORTANT RULES:
- You can ONLY create alerts for these supported assets: ${ALLOWED_ASSETS.join(", ")}
- If a user requests an alert for ANY other asset (like SOL, DOGE, ADA, XRP, etc.), you MUST respond with a text message explaining that only ${ALLOWED_ASSETS.join(
            ", "
          )} are supported
- DO NOT call the create_price_alert function if the user requests an unsupported asset
- Only call the create_price_alert function when the user requests an alert for one of the supported assets: ${ALLOWED_ASSETS.join(
            ", "
          )}`,
        },
        { role: "user", content: message },
      ],
      tools: [
        {
          type: "function",
          function: {
            name: "create_price_alert",
            description: `Create a price alert. ONLY use this function for supported assets: ${ALLOWED_ASSETS.join(
              ", "
            )}. If the user requests an unsupported asset, respond with text instead.`,
            parameters: {
              type: "object",
              properties: {
                asset: {
                  type: "string",
                  enum: [...ALLOWED_ASSETS],
                  description: `The cryptocurrency asset to monitor. MUST be one of: ${ALLOWED_ASSETS.join(", ")}`,
                },
                condition: {
                  type: "string",
                  enum: [...ALLOWED_CONDITIONS],
                  description:
                    "The price condition: gt (greater than), lt (less than), gte (greater than or equal), lte (less than or equal)",
                },
                targetPriceUsd: {
                  type: "string",
                  description: "The target price in USD (as a string to avoid precision loss — will be parsed as number)",
                },
              },
              required: ["asset", "condition", "targetPriceUsd"],
            },
          },
        },
      ],
    });

    const responseMessage = response.choices[0]?.message;

    if (!responseMessage) {
      console.log("  [ERROR] No response from Gemini");
      return res.status(500).json({ error: "No response from Gemini" });
    }

    // Handle text response from Gemini
    if (responseMessage.content && (!responseMessage.tool_calls || responseMessage.tool_calls.length === 0)) {
      console.log(`  [REPLY] "${responseMessage.content}"`);
      console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
      return res.json({ reply: responseMessage.content });
    }

    // Handle function call from Gemini
    if (responseMessage.tool_calls && responseMessage.tool_calls[0]?.function?.name === "create_price_alert") {
      let args;
      try {
        args = JSON.parse(responseMessage.tool_calls[0].function.arguments);
      } catch (parseError) {
        console.log("  [ERROR] Failed to parse function arguments");
        return res.status(500).json({ error: "Failed to parse function arguments" });
      }

      // Validate extracted parameters
      if (!ALLOWED_ASSETS.includes(args.asset)) {
        return res.status(400).json({
          error: `Asset "${args.asset}" is not supported. Only ${ALLOWED_ASSETS.join(", ")} are allowed.`,
        });
      }
      if (!ALLOWED_CONDITIONS.includes(args.condition)) {
        return res.status(400).json({
          error: `Invalid condition "${args.condition}". Must be one of: ${ALLOWED_CONDITIONS.join(", ")}`,
        });
      }

      const priceValue = typeof args.targetPriceUsd === "string" ? parseFloat(args.targetPriceUsd) : args.targetPriceUsd;
      if (isNaN(priceValue) || priceValue <= 0) {
        return res.status(400).json({
          error: "targetPriceUsd must be a positive number",
        });
      }

      console.log(`  [2] Parameters: ${args.asset} ${args.condition} $${priceValue}`);

      // Create paid alert via /alerts endpoint (x402 payment)
      console.log("  [3] Creating alert via /alerts endpoint (x402 payment)...");
      try {
        const result = await createPaidPriceAlert({
          asset: args.asset,
          condition: args.condition,
          targetPriceUsd: priceValue,
        });
        console.log(`  [SUCCESS] Alert created - ID: ${result.alert.id}`);
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        return res.json({
          reply: `Price alert created: ${args.asset} ${args.condition} $${priceValue}`,
          alert: result.alert,
          transactionHash: result.transactionHash,
        });
      } catch (paymentError: any) {
        console.log(`  [ERROR] Payment failed: ${paymentError.message}`);
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        return res.status(500).json({
          error: "Failed to create price alert",
          details: paymentError.message,
        });
      }
    } else {
      const textReply = responseMessage.content
        ? responseMessage.content
        : "I can help you create price alerts for BTC, ETH, or LINK. Try saying something like 'Create an alert when BTC is greater than 50000'.";
      console.log(`  [REPLY] "${textReply}"`);
      console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
      return res.json({ reply: textReply });
    }
  } catch (error: any) {
    if (error.status === 429 || error.statusCode === 429) {
      console.log("  [ERROR] Gemini API rate limit exceeded (429)");
      console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
      return res.status(429).json({
        error: "Rate limit exceeded",
        message: "Too many requests to Gemini API. Please try again later.",
        details: error.message || "Rate limit exceeded",
      });
    }

    const statusCode = error.status || error.statusCode || 500;
    const errorMessage = error.message || "Unknown error";

    console.log(`  [ERROR] Gemini API error: ${statusCode} - ${errorMessage}`);
    if (error.response) {
      console.log(`  [ERROR] Response status: ${error.response.status}`);
      if (error.response.data) {
        console.log(`  [ERROR] Response body: ${JSON.stringify(error.response.data, null, 2)}`);
      }
    }
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    return res.status(statusCode >= 400 && statusCode < 600 ? statusCode : 500).json({
      error: "An error occurred while processing your request",
      details: errorMessage,
      statusCode: statusCode,
    });
  }
});

/**
 * POST /alerts
 * Create a new price alert (requires x402 payment)
 *
 * This endpoint demonstrates the x402 v2 payment flow:
 * 1. Client sends request → 402 if no X-PAYMENT header
 * 2. Client retries with X-PAYMENT → Server validates via facilitator
 * 3. Server creates alert and responds with 200 + X-PAYMENT-RESPONSE settlement
 */
app.post("/alerts", (req, res) => {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("POST /alerts");

  const body = req.body as Partial<AlertRequestBody>;

  if (!body.asset || !body.condition || typeof body.targetPriceUsd !== "number") {
    console.log("  [ERROR] Missing required fields");
    return res.status(400).json({
      error: "Missing required fields",
      required: ["asset", "condition", "targetPriceUsd"],
    });
  }

  console.log("  [1] x402 v2 payment verified");

  // Extract payer address from x402 X-PAYMENT header
  let payer = "unknown";
  const paymentHeader = req.headers["x-payment"] as string | undefined;
  if (paymentHeader) {
    try {
      const decoded = decodePaymentHeader(paymentHeader);
      if ("authorization" in decoded) {
        payer = decoded.authorization.from;
      }
    } catch (e) {
      // Could not extract payer
    }
  }

  // Create alert with deterministic ID
  const alertData = {
    payer,
    asset: body.asset,
    condition: body.condition,
    targetPriceUsd: body.targetPriceUsd,
    createdAt: Math.floor(Date.now() / 1000),
  };  const alertId = createHash("sha256")
    .update(JSON.stringify(alertData))
    .digest("hex")
    .substring(0, 16);

  const storedAlert: StoredAlert = {
    id: alertId,
    ...alertData,
  };

  console.log(`  [2] Alert created: ${alertId} (${body.asset} ${body.condition} $${body.targetPriceUsd})`);
  console.log(`  [3] Payer: ${payer}`);

  // Output CRE workflow payload
  const workflowPayload = {
    id: storedAlert.id,
    asset: storedAlert.asset,
    condition: storedAlert.condition,
    targetPriceUsd: storedAlert.targetPriceUsd,
    createdAt: storedAlert.createdAt,
  };
  console.log("\n  CRE Workflow Payload:");
  console.log(`  ${JSON.stringify(workflowPayload)}`);

  console.log("\n  [SUCCESS] Alert created successfully");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

  res.json({
    alert: storedAlert,
  });
});

// ============================================================================
// Server Start
// ============================================================================

const server = app.listen(PORT, () => {
  console.log(`\nServer running on http://localhost:${PORT}`);
  console.log(`  API: http://localhost:${PORT}/alerts (x402 payment required)`);
  console.log(`  Chat: http://localhost:${PORT}/chat`);
  console.log(`  Discovery: http://localhost:${PORT}/.well-known/x402`);
  console.log(`  Health: http://localhost:${PORT}/health\n`);
});

// Start interactive chat if --chat flag is passed
if (process.argv.includes("--chat")) {
  startChatInterface(PORT);
}

export { app, server };
