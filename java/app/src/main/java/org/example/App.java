package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import spark.Spark;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;

public final class App {
    private static final String SIGNING_SECRET = System.getenv("SIGNING_SECRET");
    private static final int AES_GCM_IV_SIZE = 12;
    private static final int AES_GCM_TAG_SIZE = 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static boolean verifySignature(final byte[] secretKey, final String signature, final byte[] payload) {
        try {
            final var decodedSignature = Base64.getDecoder().decode(signature);

            final var hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(secretKey, "HmacSHA256"));

            final var expectedMac = hmac.doFinal(payload);
            return MessageDigest.isEqual(decodedSignature, expectedMac);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] decryptPayload(final byte[] secret, final byte[] cipherBody) {
        final var iv = new byte[AES_GCM_IV_SIZE];
        System.arraycopy(cipherBody, 0, iv, 0, AES_GCM_IV_SIZE);

        final var cipher = new byte[cipherBody.length - AES_GCM_IV_SIZE];
        System.arraycopy(cipherBody, AES_GCM_IV_SIZE, cipher, 0, cipher.length);

        final var plaintext = new byte[cipher.length - AES_GCM_TAG_SIZE];

        final var gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());
        final var parameters = new AEADParameters(new KeyParameter(secret), AES_GCM_TAG_SIZE * 8, iv, null);
        gcm.init(false, parameters);

        final var offset = gcm.processBytes(cipher, 0, cipher.length, plaintext, 0);

        try {
            gcm.doFinal(plaintext, offset);
        } catch (Exception error) {
            throw new RuntimeException("Decryption failed.", error);
        }

        return plaintext;
    }

    public static void main(final String[] args) {
        if (SIGNING_SECRET == null) {
            System.err.println("SIGNING_SECRET environment variable is not set");
            System.exit(1);
        }

        Spark.port(8080);

        Spark.post("/webhook", (request, response) -> {
            final var signature = request.headers("x-signature-sha256");
            if (signature == null) {
                response.status(400);
                return "Missing signature";
            }

            final var encryptedBody = request.bodyAsBytes();
            final var decodedSecret = Base64.getDecoder().decode(SIGNING_SECRET);

            if (!verifySignature(decodedSecret, signature, encryptedBody)) {
                response.status(400);
                return "Invalid signature";
            }

            try {
                final var decryptedBody = decryptPayload(decodedSecret, encryptedBody);
                final var decryptedText = new String(decryptedBody, StandardCharsets.UTF_8);
                System.out.println("Decrypted payload: " + decryptedText);
                return "OK";
            } catch (Exception e) {
                System.err.println("Error decrypting payload: " + e.getMessage());
                response.status(503);
                return "Failed to decrypt content";
            }
        });

        System.out.println("Server listening on port 8080");
    }
}
