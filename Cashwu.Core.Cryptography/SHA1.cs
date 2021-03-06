using System;
using System.Linq;
using System.Text;

namespace Cashwu.Core.Cryptography
{
    public class SHA1
    {
        public string Compute(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }

            using (var hash = System.Security.Cryptography.SHA1.Create())
            {
                return string.Concat(hash.ComputeHash(Encoding.UTF8.GetBytes(plainText)).Select(item => item.ToString("x2")));
            }
        }

        public string ComputeBase64(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }
            
            using (var hash = System.Security.Cryptography.SHA1.Create())
            {
                return Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(plainText)));
            }
        }
    }
}