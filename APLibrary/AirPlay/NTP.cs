using BitConverter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay
{
    public class NTP
    {
        public long timeRef;
        public NTP()
        {
            timeRef = DateTimeOffset.Now.ToUnixTimeMilliseconds() - (2208988800000);
        }
        
        public byte[] getNTPTimestamp()
        {
            long time = DateTimeOffset.Now.ToUnixTimeMilliseconds() - timeRef;
            long sec = (long)Math.Floor((double)time / 1000.0);
            var msec = time - sec * 1000;
            var ntp_msec = Math.Floor(msec * 4294967.296);
            byte[] data = new byte[8];
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)sec), data, 4);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)ntp_msec), 0, data, 4, 4);
            return data;
        }
    }    
}
