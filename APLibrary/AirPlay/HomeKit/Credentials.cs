using APLibrary.AirPlay.Utils;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using BitConverter;

namespace APLibrary.AirPlay.HomeKit
{
    public class Credentials
    {
        public string uniqueIdentifier;
        public byte[] identifier;
        public string pairingId;
        public byte[] publicKey;
        public byte[] encryptionKey;
        public byte[] writeKey;
        public byte[] readKey;
        public int encryptCount;
        public int decryptCount;

        public Credentials(string uniqueIdentifier, byte[] identifier, string pairingId, byte[] publicKey, byte[] encryptionKey)
        {
            this.uniqueIdentifier = uniqueIdentifier;
            this.identifier = identifier;
            this.pairingId = pairingId;
            this.publicKey = publicKey;
            this.encryptionKey = encryptionKey;
            this.encryptCount = 0;
            this.decryptCount = 0;
        }

        public static Credentials parse(string text)
        {
            string[] lines = text.Split(':');
            return new Credentials(lines[0], Convert.FromHexString(lines[1]), Convert.FromHexString(lines[2]).ToString(), Convert.FromHexString(lines[3]), Convert.FromHexString(lines[4]));
        }

        public string toString()
        {
            return this.uniqueIdentifier + ":" + Convert.ToHexString(this.identifier) + ":" + Convert.ToHexString(Encoding.ASCII.GetBytes(this.pairingId)) + ":" + Convert.ToHexString(this.publicKey) + ":" + Convert.ToHexString(this.encryptionKey);

        }

        public byte[] encrypt(byte[] message)
        {
            int offset = 0;
            int total = message.Length;
            byte[] result = new byte[0];
            while (offset < total)
            {
                int length = Math.Min(total - offset, 1024);
                byte[] s1length_bytes = EndianBitConverter.LittleEndian.GetBytes(Convert.ToUInt16(length));
                (byte[] s1ct, byte[] s1tag) = Encryption.EncryptAndSeal(message.Skip(offset).Take(length).ToArray(), s1length_bytes, (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(EndianBitConverter.LittleEndian.GetBytes(Convert.ToUInt64(this.encryptCount))).ToArray(), this.writeKey);

                byte[] ciphertext = s1length_bytes.Concat(s1ct).ToArray().Concat(s1tag).ToArray();
                offset += length;
                this.encryptCount += 1;
                result = result.Concat(ciphertext).ToArray();
            }
            return result;
        }
        public byte[] decrypt(byte[] message)
        {
            int offset = 0;
            byte[] result = new byte[0];
            while (offset < message.Length)
            {
                byte[] lengthbytes = message.Skip(offset).Take(2).ToArray();
                int length = EndianBitConverter.LittleEndian.ToUInt16(lengthbytes, 0);
                byte[] messagea = message.Skip(offset + 2).Take(length + 16).ToArray();
                byte[] cipherText = messagea.Skip(0).Take(messagea.Length - 16).ToArray();
                byte[] hmac = messagea.Skip(messagea.Length - 16).ToArray();
                byte[] decrypted = Encryption.VerifyAndDecrypt(cipherText, hmac, lengthbytes, (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(EndianBitConverter.LittleEndian.GetBytes(Convert.ToUInt64(this.decryptCount))).ToArray(), this.readKey);
                this.decryptCount += 1;
                offset = offset + length + 16 + 2;
                result = result.Concat(decrypted).ToArray();
            }
            return result;
        }
        public byte[] EncryptAudio(byte[] message, byte[] aad, int nonce) {
            (byte[] ct, byte[] tag) = Encryption.EncryptAndSeal(message, aad, EndianBitConverter.LittleEndian.GetBytes(Convert.ToUInt64(nonce)), this.writeKey);
            return (ct.Concat(tag).ToArray()).Concat(EndianBitConverter.LittleEndian.GetBytes(Convert.ToUInt64(nonce))).ToArray();
        }
    }    
}
