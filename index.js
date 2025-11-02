import express from "express";
import crypto from "node:crypto";
import validator from "validator";
import axios from "axios";
import { json } from "express";

const app = express();

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

app.use(json({ limit: "100kb" }));

// Ensure all responses have proper content-type
app.use((req, res, next) => {
    res.setHeader('Content-Type', 'application/json');
    next();
});

app.get("/", (_req, res) => {
    return res.json({
        message: "🔐 HIBP Proxy API is up and running!",
        usage: {
            POST: "/password-check",
            docs: "https://haveibeenpwned.com/API/v3#PwnedPasswords"
        },
        timestamp: new Date().toISOString()
    });
});

app.post("/password-check", async (req, res) => {
    try {
        console.log("📥 Request received:", JSON.stringify(req.body, null, 2));

        if (!req.body || !validator.isJSON(JSON.stringify(req.body))) {
            console.log("❌ Invalid JSON");
            return res.status(400).json({
                actionStatus: "ERROR",
                error: "invalid_request",
                errorDescription: "Invalid JSON payload."
            });
        }

        const cred = req.body?.event?.user?.updatingCredential;
        if (!cred || cred.type !== "PASSWORD") {
            console.log("❌ No password credential");
            return res.status(400).json({
                actionStatus: "ERROR",
                error: "invalid_credential",
                errorDescription: "No password credential found."
            });
        }

        // Handle encrypted (base64-encoded) or plain text passwords
        let plain = cred.value;
        if (cred.format === "HASH") {
            try {
                plain = Buffer.from(cred.value, "base64").toString("utf8");
                console.log("✅ Decoded password");
            } catch (err) {
                console.log("❌ Failed to decode:", err.message);
                return res.status(400).json({
                    actionStatus: "ERROR",
                    error: "invalid_credential",
                    errorDescription: "Expects the encrypted credential."
                });
            }
        }

        const sha1 = crypto.createHash("sha1").update(plain).digest("hex").toUpperCase();
        const prefix = sha1.slice(0, 5);
        const suffix = sha1.slice(5);

        console.log("🔍 Checking HIBP...");

        const hibpResp = await axios.get(
            `https://api.pwnedpasswords.com/range/${prefix}`,
            {
                headers: {
                    "Add-Padding": "true",
                    "User-Agent": "asgardeo-hibp-checker"
                },
                timeout: 8000
            }
        );

        const hitLine = hibpResp.data
            .split("\n")
            .find((line) => line.startsWith(suffix));

        const count = hitLine ? parseInt(hitLine.split(":")[1], 10) : 0;

        if (count > 0) {
            console.log(`❌ Password compromised: ${count} breaches`);
            const failureResponse = {
                actionStatus: "FAILED",
                failureReason: "password_compromised",
                failureDescription: "The provided password is compromised."
            };
            console.log("📤 Sending:", JSON.stringify(failureResponse));
            return res.status(200).json(failureResponse);
        }

        console.log("✅ Password safe");
        const successResponse = { actionStatus: "SUCCESS" };
        console.log("📤 Sending:", JSON.stringify(successResponse));
        return res.status(200).json(successResponse);
        
    } catch (err) {
        console.error("🔥 Error:", err.message);
        console.error(err.stack);
        
        const status = err.response?.status || 500;
        const msg = status === 429
            ? "External HIBP rate limit hit—try again in a few seconds."
            : err.message || "Unexpected server error";
        
        const errorResponse = {
            actionStatus: "ERROR",
            error: "service_error",
            errorDescription: msg
        };
        console.log("📤 Error response:", JSON.stringify(errorResponse));
        return res.status(500).json(errorResponse);
    }
});

// Handle 404
app.use((req, res) => {
    return res.status(404).json({
        error: "not_found",
        path: req.path
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error("🔥 Unhandled error:", err);
    return res.status(500).json({
        actionStatus: "ERROR",
        error: "internal_error",
        errorDescription: "An unexpected error occurred"
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server started on port ${PORT}`);
});

export default app;
