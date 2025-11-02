import express from "express";
import crypto from "node:crypto";
import validator from "validator";
import axios from "axios";
import { json } from "express";

const app = express();

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

app.use(json({ limit: "100kb" }));

app.get("/", (_req, res) => {
    console.log("👋 Health check endpoint accessed at", new Date().toISOString());
    res.json({
        message: "🔐 HIBP Proxy API is up and running!",
        usage: {
            POST: "/password-check",
            docs: "https://haveibeenpwned.com/API/v3#PwnedPasswords"
        },
        timestamp: new Date().toISOString()
    });
});

app.post("/password-check", async (req, res) => {
    console.log("🔍 Password check request received:", {
        timestamp: new Date().toISOString(),
        hasBody: !!req.body,
        bodyKeys: Object.keys(req.body || {})
    });
    
    try {
        if (!validator.isJSON(JSON.stringify(req.body))) {
            console.log("❌ Invalid JSON payload detected");
            return res.status(400).json({
                actionStatus: "ERROR",
                error: "invalid_request",
                errorDescription: "Invalid JSON payload."
            });
        }

        const cred = req.body?.event?.user?.updatingCredential;
        console.log("📋 Credential extracted:", {
            hasCredential: !!cred,
            credentialType: cred?.type,
            credentialFormat: cred?.format,
            hasValue: !!cred?.value
        });
        
        if (!cred || cred.type !== "PASSWORD") {
            console.log("❌ No valid password credential found");
            return res.status(400).json({
                actionStatus: "ERROR",
                error: "invalid_credential",
                errorDescription: "No password credential found."
            });
        }

        // Handle encrypted (base64-encoded) or plain text passwords
        let plain = cred.value;
        if (cred.format === "HASH") {
            console.log("🔐 Processing encrypted credential");
            try {
                plain = Buffer.from(cred.value, "base64").toString("utf8");
                console.log("✅ Successfully decoded base64 credential");
            } catch {
                console.log("❌ Failed to decode base64 credential");
                return res.status(400).json({
                    actionStatus: "ERROR",
                    error: "invalid_credential",
                    errorDescription: "Expects the encrypted credential."
                });
            }
        } else {
            console.log("📝 Processing plain text credential");
        }

        const sha1 = crypto.createHash("sha1").update(plain).digest("hex").toUpperCase();
        const prefix = sha1.slice(0, 5);
        const suffix = sha1.slice(5);
        
        console.log("🔑 SHA1 hash generated:", {
            prefix,
            suffixLength: suffix.length
        });

        console.log("🌐 Making request to HIBP API...");
        const hibpResp = await axios.get(
            `https://api.pwnedpasswords.com/range/${prefix}`,
            {
                headers: {
                    "Add-Padding": "true",
                    "User-Agent": "asgardeo-hibp-checker"
                }
            }
        );
        
        console.log("📡 HIBP API response received:", {
            status: hibpResp.status,
            dataLength: hibpResp.data.length,
            lineCount: hibpResp.data.split("\n").length
        });

        const hitLine = hibpResp.data
            .split("\n")
            .find((line) => line.startsWith(suffix));

        const count = hitLine ? parseInt(hitLine.split(":")[1], 10) : 0;
        
        console.log("🔍 Password breach check result:", {
            found: !!hitLine,
            breachCount: count,
            hitLine: hitLine ? hitLine.substring(0, 10) + "..." : null
        });

        if (count > 0) {
            console.log(`🚨 Password compromised! Found in ${count.toLocaleString()} breaches`);
            return res.status(200).json({
                actionStatus: "FAILED",
                failureReason: "password_compromised",
                failureDescription: `This password has appeared in ${count.toLocaleString()} data breaches. Please choose a different password.`
            });
        }

        console.log("✅ Password is clean - not found in breaches");
        return res.json({ actionStatus: "SUCCESS" });
    } catch (err) {
        console.error("🔥 Error occurred during password check:", {
            message: err.message,
            status: err.response?.status,
            statusText: err.response?.statusText,
            data: err.response?.data,
            stack: err.stack
        });
        
        const status = err.response?.status || 500;
        const msg =
            status === 429
                ? "External HIBP rate limit hit—try again in a few seconds."
                : err.message || "Unexpected server error";
                
        console.log(`📤 Sending error response with status ${status}:`, msg);
        res.status(status).json({ 
            actionStatus: "ERROR",
            error: "service_error",
            errorDescription: msg 
        });
    }
});

app.listen(PORT, () => {
    console.log(
        `🚀  HIBP Proxy API server started on http://localhost:${PORT} — ` +
        "press Ctrl+C to stop"
    );
});

export default app;