using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var signingSecret = Environment.GetEnvironmentVariable("SIGNING_SECRET")
    ?? throw new InvalidOperationException("SIGNING_SECRET environment variable is not set");

bool VerifySignature(byte[] secretKey, string signature, byte[] payload)
{
    try
    {
        var decodedSignature = Convert.FromBase64String(signature);
        using var hmac = new HMACSHA256(secretKey);
        var expectedMac = hmac.ComputeHash(payload);
        return decodedSignature.SequenceEqual(expectedMac);
    }
    catch
    {
        return false;
    }
}

const int AES_GCM_IV_SIZE = 12;
const int AES_GCM_TAG_SIZE = 16;

byte[] DecryptPayload(byte[] secret, byte[] cipherBody)
{
    var cipher = cipherBody.Skip(AES_GCM_IV_SIZE).Take(cipherBody.Length - AES_GCM_IV_SIZE).ToArray();
    var iv = cipherBody.Take(AES_GCM_IV_SIZE).ToArray();

    var plaintextBytes = new byte[cipher.Length - AES_GCM_TAG_SIZE];

    var gcm = new GcmBlockCipher(new AesEngine());
    var parameters = new AeadParameters(new KeyParameter(secret), AES_GCM_TAG_SIZE * 8, iv);
    gcm.Init(false, parameters);

    var offset = gcm.ProcessBytes(cipher, 0, cipher.Length, plaintextBytes, 0);
    gcm.DoFinal(plaintextBytes, offset);

    return plaintextBytes;
}

app.MapPost("/webhook", async (HttpContext context) =>
{
    var signature = context.Request.Headers["x-signature-sha256"].ToString();
    if (string.IsNullOrEmpty(signature))
    {
        return Results.BadRequest("Missing signature");
    }

    var memory = new MemoryStream();
    await context.Request.Body.CopyToAsync(memory);
    var encryptedBody = memory.ToArray();
    var decodedSecret = Convert.FromBase64String(signingSecret);

    if (!VerifySignature(decodedSecret, signature, encryptedBody))
    {
        return Results.BadRequest("Invalid signature");
    }

    try
    {
        var decryptedBody = DecryptPayload(decodedSecret, encryptedBody);
        var decryptedText = Encoding.UTF8.GetString(decryptedBody);
        Console.WriteLine($"Decrypted payload: {decryptedText}");
        return Results.Ok("OK");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error decrypting payload: {ex}");
        return Results.StatusCode(503);
    }
});

app.Run("http://localhost:8080");
