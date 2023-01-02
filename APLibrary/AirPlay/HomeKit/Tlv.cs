using BitConverter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.HomeKit
{
    public static class TlvTag
    {
        public const byte PairingMethod = 0x00;
        public const byte Username = 0x01;
        public const byte Salt = 0x02;
        // could be either the SRP client public key (384 bytes) or the ED25519 public key (32 bytes), depending on context
        public const byte PublicKey = 0x03;
        public const byte Proof = 0x04;
        public const byte EncryptedData = 0x05;
        public const byte Sequence = 0x06;
        public const byte ErrorCode = 0x07;
        public const byte BackOff = 0x08;
        public const byte Signature = 0x0A;
        public const byte MFiCertificate = 0x09;
        public const byte MFiSignature = 0x0A;
        public const byte Flags = 0x13;
    }
    
    public class Tlv
    {
        
    public static byte[] Encode(Dictionary<byte, byte[]> dict)
    {
            var encodedTLVBuffer = new byte[0];
            
            foreach (KeyValuePair<byte, byte[]> kvp in dict)
            {

                // coerce data to Buffer if needed
                // if (data === 'number')
                //     data = Buffer.from([data]);
                //else if (typeof data === 'string')
                //     data = Buffer.from(data);
                var encodedTLVBuffertmp = new byte[0];
                if (kvp.Value.Length <= 255)
                {
                    encodedTLVBuffertmp = (new byte[] { kvp.Key }).Concat(new byte[] { (byte)kvp.Value.Length }).Concat(kvp.Value).ToArray();
                }
                else
                {
                    var leftLength = kvp.Value.Length;
                    byte[] tempBuffer = new byte[0];
                    int currentStart = 0;
                    for (; leftLength > 0;)
                    {
                        if (leftLength >= 255)
                        {
                            tempBuffer = tempBuffer.Concat((new byte[] { kvp.Key }).Concat(new byte[] { 0xFF }).Concat(kvp.Value.Skip(currentStart).Take(255).ToArray()).ToArray()).ToArray();
                            leftLength -= 255;
                            currentStart = currentStart + 255;
                        } else {
                            tempBuffer = tempBuffer = tempBuffer.Concat((new byte[] { kvp.Key }).Concat(new byte[] { (byte) leftLength }).Concat(kvp.Value.Skip(currentStart).Take(leftLength).ToArray()).ToArray()).ToArray();
                            leftLength -= leftLength;
                        }
                    }
                    encodedTLVBuffertmp = tempBuffer;
                }

                encodedTLVBuffer = encodedTLVBuffer.Concat(encodedTLVBuffertmp).ToArray();
            }
            return encodedTLVBuffer;
    }
    
    public static Dictionary<byte, byte[]> Decode(byte[] data)
    {
        Dictionary<byte, byte[]> objects = new Dictionary<byte, byte[]>();
        var leftLength = data.Length;
        var currentIndex = 0;
        for (; leftLength > 0;)
        {
            byte type = data[currentIndex];
            byte length = data[currentIndex + 1];
            currentIndex += 2;
            leftLength -= 2;
            byte[] newData = data.Skip(currentIndex).Take(length).ToArray();
            if (objects.ContainsKey(type))
            {
                (objects[type]) = objects[type].Concat(newData).ToArray();
            } else {
                objects[type] = newData;
            }
            currentIndex += length;
            leftLength -= length;
        }
            return objects;
        }

    }
}
