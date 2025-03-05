using System.Security.Cryptography.X509Certificates;

namespace DemoClient;

internal class Program
{
    
    static async Task Main(string[] args)
    {
        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(X509Certificate2.CreateFromPemFile("client.crt", "client.key"));
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            // creamos una política de validación de certificados
            var chainPolicy = new X509ChainPolicy
            {
                // ignoramos la revocación de los certificados
                RevocationFlag = X509RevocationFlag.EntireChain,
                // validamos la cadena de certificados
                RevocationMode = X509RevocationMode.NoCheck,
                // le indicamos que la cadena de confianza la vamos a especificar nosotros
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                // validamos la fecha de caducidad
                VerificationTimeIgnored = false
            };

            // añadimos la CA como raíz de confianza
            var rootcert = new X509Certificate2("ca.crt");
            chainPolicy.CustomTrustStore.Clear();
            chainPolicy.CustomTrustStore.Add(rootcert);

            // asignamos la política de validación a la cadena de certificados
            chain ??= new X509Chain();
            chain.ChainPolicy = chainPolicy;

            // validamos el certificado que nos viene del servidor
            var certificateIsValid = chain.Build(cert);
            return certificateIsValid;
        };

        var client = new HttpClient(handler);
        var response = await client.GetAsync("https://localhost:7180/");
        Console.WriteLine(response.StatusCode);
        Console.WriteLine(await response.Content.ReadAsStringAsync());
    }
}