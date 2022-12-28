using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.Utils
{
    public class Utils
    {
        public static int randomInt(int n)
        {
            return (int) Math.Floor(new Random().Next(0,1) * Math.Pow(10, n));
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
    }
}
