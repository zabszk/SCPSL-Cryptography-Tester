using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace SL_Cryptography_Tester
{
    public class ECDSA
    {
        public static AsymmetricCipherKeyPair GenerateKeys(int size = 384)
        {
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var keyGenParam = new KeyGenerationParameters(secureRandom, size);
            gen.Init(keyGenParam);
            return gen.GenerateKeyPair();
        }

        public static string Sign(string data, AsymmetricKeyParameter privKey)
        {
            return Convert.ToBase64String(SignBytes(data, privKey));
        }

        public static byte[] SignBytes(string data, AsymmetricKeyParameter privKey)
        {
            var decodedData = Encoding.UTF8.GetBytes(data);
            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, privKey);
            signer.BlockUpdate(decodedData, 0, data.Length);
            var sigBytes = signer.GenerateSignature();
            return sigBytes;
        }

        public static bool Verify(string data, string signature, AsymmetricKeyParameter pubKey)
        {
            return VerifyBytes(data, Convert.FromBase64String(signature), pubKey);
        }

        public static bool VerifyBytes(string data, byte[] signature, AsymmetricKeyParameter pubKey)
        {

            var decodedData = Encoding.UTF8.GetBytes(data);
            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(false, pubKey);
            signer.BlockUpdate(decodedData, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public static AsymmetricKeyParameter PublicKeyFromString(string key)
        {
            TextReader reader = new StringReader(key);
            var pemReader = new PemReader(reader);
            return (AsymmetricKeyParameter)pemReader.ReadObject();
        }

        public static string KeyToString(AsymmetricKeyParameter key)
        {
            TextWriter textWriter = new StringWriter();
            var pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(key);
            pemWriter.Writer.Flush();

            return textWriter.ToString();
        }
    }
}
