using System;
using System.IO;
using System.Security.Cryptography;

namespace Cashwu.Core.Cryptography
{
    public class AES
    {
        /// <summary>
        /// Generator AES key and iv
        /// </summary>
        /// <returns>Tuple (string key, string iv), Base64 encoding</returns>
        public (string key, string iv) GeneratorKeyAndIv()
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();
                return (Convert.ToBase64String(aes.Key), Convert.ToBase64String(aes.IV));
            } 
        }
        
        /// <summary>
        /// Encrypt 
        /// </summary>
        /// <param name="plainText">plain text</param>
        /// <param name="key">Base64 key text</param>
        /// <param name="iv">Base64 iv text</param>
        /// <returns></returns>
        public string Encrypt(string plainText, string key, string iv)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrWhiteSpace(iv))
            {
                throw new ArgumentNullException(nameof(iv));
            }

            var keyBytes = Convert.FromBase64String(key);
            var ivBytes = Convert.FromBase64String(iv);

            return Convert.ToBase64String(Encrypt(plainText, keyBytes, ivBytes));
        }

        /// <summary>
        /// Decrypt 
        /// </summary>
        /// <param name="encryptText">encrypt text</param>
        /// <param name="key">Base64 key text</param>
        /// <param name="iv">Base64 iv text</param>
        /// <returns></returns>
        public string Decrypt(string encryptText, string key, string iv)
        {
            if (string.IsNullOrWhiteSpace(encryptText))
            {
                throw new ArgumentNullException(nameof(encryptText));
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrWhiteSpace(iv))
            {
                throw new ArgumentNullException(nameof(iv));
            }

            var keyBytes = Convert.FromBase64String(key);
            var ivBytes = Convert.FromBase64String(iv);
            var text = Convert.FromBase64String(encryptText);

            return Decrypt(text, keyBytes, ivBytes);
        }

        private static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
        {
            byte[] encrypted;

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encrypt, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        private static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            string plaintext;

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var decrypt = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decrypt, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}