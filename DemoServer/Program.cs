
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// Abre una terminal y ejecuta los siguientes comandos para generar los certificados:
// 
// 1. Crear la clave privada de la CA
// openssl genrsa -out ca.key 4096
// 
// 2. Crear el certificado de la CA
// openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=MyCA"
// 
// 3. Crear la clave privada del servidor
// openssl genrsa -out server.key 2048
// 
// 4. Crear una solicitud de firma de certificado (CSR) del servidor
// openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
// 
// 5. Firmar el certificado del servidor con la CA
// openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
// 
// 6. Crear la clave privada del cliente
// openssl genrsa -out client.key 2048
// 
// 7. Crear una solicitud de firma de certificado (CSR) del cliente
// openssl req -new -key client.key -out client.csr -subj "/CN=client"
// 
// 8. Firmar el certificado del cliente con la CA
// openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
// 
// 9. Generar el archivo PKCS#12 (.pfx) para el servidor y el cliente
// openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -password pass:password
// openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -password pass:password



namespace DemoServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();

            // Configuración de Kestrel para usar HTTPS y autenticación mTLS
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ConfigureHttpsDefaults(httpsOptions =>
                {
                    httpsOptions.ServerCertificate = X509Certificate2.CreateFromPemFile("server.crt", "server.key");
                    httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    httpsOptions.AllowAnyClientCertificate();
                });
            });

            builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                .AddCertificate(options =>
                {
                    options.RevocationMode = X509RevocationMode.NoCheck;
                    options.ValidateValidityPeriod = true;
                    options.AllowedCertificateTypes = CertificateTypes.Chained;
                    options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;

                    var rootCert = X509CertificateLoader.LoadCertificateFromFile("ca.crt");
                    options.CustomTrustStore.Clear();
                    options.CustomTrustStore.Add(rootCert);
                });

            builder.Services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapPost("/secure-data", async (HttpContext context) =>
            {
                if (context.Connection.ClientCertificate == null)
                {
                    return Results.BadRequest("No se proporcionó certificado de cliente");
                }

                // Descifrar y verificar la solicitud
                var encryptedData = await context.Request.BodyReader.ReadAsync();
                byte[] decryptedData = DecryptData(encryptedData.Buffer.ToArray(), "server.key");
                bool isVerified = VerifySignature(decryptedData, "client.crt");
                if (!isVerified)
                {
                    return Results.BadRequest("Firma inválida");
                }

                // Firmar y cifrar la respuesta
                byte[] responseData = Encoding.UTF8.GetBytes("Datos seguros enviados");
                byte[] signedResponse = SignData(responseData, "server.key");
                byte[] encryptedResponse = EncryptData(signedResponse, "client.crt");

                return Results.Bytes(encryptedResponse);
            });

            app.Run();
        }

        /* Funciones auxiliares */
        static byte[] SignData(byte[] data, string privateKeyPath)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(privateKeyPath));
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        static bool VerifySignature(byte[] data, string certPath)
        {
            using var cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            using RSA rsa = cert.GetRSAPublicKey();
            return rsa.VerifyData(data, data[^256..], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        static byte[] EncryptData(byte[] data, string certPath)
        {
            using var cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            using RSA rsa = cert.GetRSAPublicKey();
            return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        }

        static byte[] DecryptData(byte[] data, string privateKeyPath)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(privateKeyPath));
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
        }
    }
}
