using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.Utils
{
    public class Utils
    {
        public static long randomInt(int n)
        {
            var random = new Random();
            string s = string.Empty;
            for (int i = 0; i < n; i++)
                s = String.Concat(s, random.Next(10).ToString());
            return long.Parse(s);
        }

        public static string randomHex(int digits)
        {
            Random random = new Random();
            byte[] buffer = new byte[digits / 2];
                random.NextBytes(buffer);
                string result = String.Concat(buffer.Select(x => x.ToString("X2")).ToArray());
                if (digits % 2 == 0)
                    return result;
                return result + random.Next(16).ToString("X");
     
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string CreateMD5(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                return Convert.ToHexString(hashBytes); // .NET 5 +

                // Convert the byte array to hexadecimal string prior to .NET 5
                // StringBuilder sb = new System.Text.StringBuilder();
                // for (int i = 0; i < hashBytes.Length; i++)
                // {
                //     sb.Append(hashBytes[i].ToString("X2"));
                // }
                // return sb.ToString();
            }
        }
    }
}
