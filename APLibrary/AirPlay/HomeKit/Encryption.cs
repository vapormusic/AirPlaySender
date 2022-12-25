using BitConverter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.HomeKit
{
    internal class Encryption
    {
        public static byte[]? VerifyAndDecrypt(byte[] cipherText, byte[] mac, byte[]? AAD, byte[] nonce, byte[] key) {
            try
            {
                if (nonce.Length == 8) nonce = (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(nonce).ToArray();
                var decipher = new NaCl.Core.ChaCha20Poly1305(key);
                byte[] plaintext = new byte[cipherText.Length];
                decipher.Decrypt(nonce, cipherText, mac, plaintext, AAD);
                return plaintext;
            } catch (Exception e)
            {
                return null;
            }
        }
        
        public static (byte[], byte[]) EncryptAndSeal(byte[] plainText, byte[]? AAD, byte[] nonce, byte[] key)
        {
            if (nonce.Length == 8) nonce = (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(nonce).ToArray();
            var cipher = new NaCl.Core.ChaCha20Poly1305(key);
            byte[] cipherText = new byte[plainText.Length];
            byte[] hmac = new byte[16];
            cipher.Encrypt(nonce, plainText, cipherText, hmac, AAD);
            return (cipherText, hmac);
        }

        public static byte[] HKDF(byte[] salt, byte[] ikm, byte[] info, int size) {
            // Only use SHA-512 as HomeKit
            var hashLength = 512 / 8;

            // now we compute the PRK            
            var hmac = new HMACSHA512(salt);
            byte[] prk = hmac.ComputeHash(ikm);
            var prev = new byte[0];
            byte[] output;
            byte[] buffers = new byte[0];
            var num_blocks = Math.Ceiling((double)(size / hashLength));
            for (var i = 0; i < num_blocks; i++)
            {
                var hmac1 = new HMACSHA512(prk);
                var u = ((char)(i + 1));
                byte[] input = (prev.Concat(info).ToArray()).Concat(new UnicodeEncoding().GetBytes(u.ToString())).ToArray();
                prev = hmac1.ComputeHash(input);
                buffers = buffers.Concat(prev).ToArray();
            }
            output = buffers.Skip(0).Take(size).ToArray();
            return output.Skip(0).Take(size).ToArray();
        }
    }
}
