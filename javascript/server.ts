import { crypto, timingSafeEqual } from "@std/crypto";
import { decodeBase64  } from "@std/encoding";

const SIGNING_SECRET = Deno.env.get("SIGNING_SECRET");
if (!SIGNING_SECRET) {
  console.error("SIGNING_SECRET environment variable is not set");
  Deno.exit(1);
}

async function verifySignature(secretKey: Uint8Array, signature: string, payload: Uint8Array): Promise<boolean> {
  try {
    const decodedSignature = decodeBase64(signature);
    const key = await crypto.subtle.importKey(
      "raw",
      secretKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const expectedMac = await crypto.subtle.sign("HMAC", key, payload);
    return timingSafeEqual(decodedSignature, expectedMac);
  } catch {
    return false;
  }
}

async function decryptPayload(secret: Uint8Array, cipherBody: Uint8Array): Promise<ArrayBuffer> {
  const nonceSize = 12;
  const nonce = cipherBody.slice(0, nonceSize);
  const ciphertext = cipherBody.slice(nonceSize);

  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  return await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    ciphertext
  );
}

Deno.serve({ port: 8080 }, async (req) => {
  if (req.method !== "POST" || new URL(req.url).pathname !== "/webhook") {
    return new Response("Not Found", { status: 404 });
  }

  const signature = req.headers.get("x-signature-sha256");
  if (!signature) {
    return new Response("Missing signature", { status: 400 });
  }

  const encryptedBody = new Uint8Array(await req.arrayBuffer());
  const decodedSecret = decodeBase64(SIGNING_SECRET);

  if (!await verifySignature(decodedSecret, signature, encryptedBody)) {
    return new Response("Invalid signature", { status: 400 });
  }

  try {
    const decryptedBody = await decryptPayload(decodedSecret, encryptedBody);
    const decryptedText = new TextDecoder().decode(decryptedBody);
    console.log("Decrypted payload:", decryptedText);
    return new Response("OK");
  } catch (error) {
    console.error("Error decrypting payload:", error);
    return new Response("Failed to decrypt content", { status: 503 });
  }
});
