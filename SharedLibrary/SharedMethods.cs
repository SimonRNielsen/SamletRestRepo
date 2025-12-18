using System.Text;
using System.Security.Cryptography;

namespace SharedLibrary
{

    public class SharedMethods
    {

        /// <summary>
        /// Decrypts a string formatted for transmission via Json/RESTful server
        /// </summary>
        /// <param name="input">Encrypted string from server</param>
        /// <returns>Decrypted string</returns>
        public static string RSADecryptStringToString(string input, string privateKey)
        {

            byte[] bytes = Convert.FromBase64String(input);

            using (RSA rsa = RSA.Create())
            {

                rsa.FromXmlString(privateKey);
                return Encoding.UTF8.GetString(rsa.Decrypt(bytes, RSAEncryptionPadding.Pkcs1));

            }

        }

        /// <summary>
        /// Encrypts and formats string for serialization into Json format to POSTing @ server
        /// </summary>
        /// <param name="input">String that must be encrypted using the recipients public key</param>
        /// <returns>Encrypted and formatted string</returns>
        public static string RSAEncryptStringToString(string input, string publicKey)
        {

            byte[] bytes = Encoding.UTF8.GetBytes(input);

            using (RSA rsa = RSA.Create())
            {

                rsa.FromXmlString(publicKey);
                return Convert.ToBase64String(rsa.Encrypt(bytes, RSAEncryptionPadding.Pkcs1));

            }

        }

        /// <summary>
        /// Forms a private and public key pair for RSA encryption
        /// </summary>
        /// <param name="privateKey">Private key returned</param>
        /// <param name="publicKey">Public key returned</param>
        public static void FormRSAKeys(out string privateKey, out string publicKey)
        {

            using (RSA rsa = RSA.Create())
            {

                privateKey = rsa.ToXmlString(true);
                publicKey = rsa.ToXmlString(false);

            }

        }

    }

}
