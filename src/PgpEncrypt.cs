using System.Net;
using System.Text;
using Ardalis.GuardClauses;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore;

namespace Bco.PgpEncrypt;

public static class PgpEncrypt
{
    [Function("PgpEncrypt")]
    public static async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req,
        FunctionContext executionContext)
    {
        var logger = executionContext.GetLogger("PGPEncrypt");
        logger.LogInformation($"{nameof(PgpEncrypt)} processed a request.");

        // read keys from environment variables
        
        var publicKeyBase64 =
            Guard.Against.NullOrEmpty(Environment.GetEnvironmentVariable("pgp-public-key"));
        
        var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
        var publicKey = Encoding.UTF8.GetString(publicKeyBytes);

        try
        {
            // encrypt and sign request body
            
            var encryptedDataStream = await EncryptAndSignAsync(req.Body, publicKey);

            // convert encryptedDataStream to byte array
            
            var encryptedData = new byte[encryptedDataStream.Length];
            await encryptedDataStream.ReadAsync(encryptedData.AsMemory(0, (int)encryptedDataStream.Length));

            // write encrypted byte array to response
            
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "application/octet-stream");
            response.Headers.Add("Content-Disposition", "attachment; filename=\"response.bin\"");
            await response.WriteBytesAsync(encryptedData);
            return response;
        }
        catch (PgpException pgpException)
        {
            var response = req.CreateResponse(HttpStatusCode.InternalServerError);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
            await response.WriteStringAsync(pgpException.Message);
            return response;
        }
    }
    
    private static async Task<Stream> EncryptAndSignAsync(Stream inputStream, string publicKey)
    {
        using var pgp = new PGP(new EncryptionKeys(publicKey));
        var outputStream = new MemoryStream();
        await using (inputStream)
        {
            await pgp.EncryptStreamAsync(inputStream, outputStream);
            outputStream.Seek(0, SeekOrigin.Begin);
            return outputStream;
        }
    }
}