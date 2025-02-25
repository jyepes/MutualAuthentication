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

namespace DemoClient
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(X509CertificateLoader.LoadPkcs12FromFile("client.pfx", "password"));
            var client = new HttpClient(handler);

            // Firmar y cifrar la solicitud
            byte[] requestData = Encoding.UTF8.GetBytes("Solicitud de datos seguros");
            byte[] signedRequest = SignData(requestData, "client.key");
            byte[] encryptedRequest = EncryptData(signedRequest, "server.crt");

            var content = new ByteArrayContent(encryptedRequest);
            var response = await client.PostAsync("https://localhost:7180/secure-data", content);
            byte[] encryptedResponse = await response.Content.ReadAsByteArrayAsync();

            // Descifrar y verificar la respuesta
            byte[] decryptedResponse = DecryptData(encryptedResponse, "client.key");
            bool isVerifiedResponse = VerifySignature(decryptedResponse, "server.crt");
            Console.WriteLine(isVerifiedResponse ? "Respuesta verificada con éxito" : "Firma de respuesta inválida");


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
            using X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            using RSA rsa = cert.GetRSAPublicKey();
            return rsa.VerifyData(data, data[^256..], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        static byte[] EncryptData(byte[] data, string certPath)
        {
            using X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
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