using System;
using System.Security.Cryptography;
using System.Web;

namespace EP.IdentityIsolation.Infra.CrossCutting.Identity.Provider
{
    public static class RandomOAuthStateGenerator
    {
        private static readonly RandomNumberGenerator _random = new RNGCryptoServiceProvider();

        public static string Generate(int strengthInBits)
        {
            const int bitsPerByte = 8;

            if (strengthInBits % bitsPerByte != 0)
            {
                throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
            }

            var strengthInBytes = strengthInBits / bitsPerByte;

            var data = new byte[strengthInBytes];
            _random.GetBytes(data);
            return HttpServerUtility.UrlTokenEncode(data);
        }
    }
}