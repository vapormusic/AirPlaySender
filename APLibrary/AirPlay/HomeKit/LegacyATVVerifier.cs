using BitConverter;
using Dorssel.Security.Cryptography;
using Microsoft.VisualBasic;
using Rebex.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.HomeKit
{
    internal class LegacyATVVerifier
    {

        public static string pair_setup_aes_key(string K)
        {
            using (SHA512 shaM = new SHA512Managed())
            {
                byte[] hash = shaM.ComputeHash(Encoding.ASCII.GetBytes("Pair-Setup-AES-Key").Concat(Utils.Utils.HexStringToByteArray(K)).ToArray());
                return Convert.ToHexString(hash).Substring(0, 32);
            }
            
                
        }

        public static string pair_setup_aes_iv(string K)
        {
            using (SHA512 shaM = new SHA512Managed())
            {
                byte[] hash = shaM.ComputeHash(Encoding.ASCII.GetBytes("Pair-Setup-AES-IV").Concat(Utils.Utils.HexStringToByteArray(K)).ToArray());
                hash = hash.Skip(0).Take(16).ToArray();
                hash[hash.Length - 1] += 0x01;
                return Convert.ToHexString(hash);
            }
        }

        public static string pair_verify_aes_key(string shared)
        {
            using (SHA512 shaM = new SHA512Managed())
            {
                byte[] hash = shaM.ComputeHash(Encoding.ASCII.GetBytes("Pair-Verify-AES-Key").Concat(Utils.Utils.HexStringToByteArray(shared)).ToArray());
                hash = hash.Skip(0).Take(16).ToArray();
                return Convert.ToHexString(hash);
            }
        }

        public static string pair_verify_aes_iv(string shared)
        {
            using (SHA512 shaM = new SHA512Managed())
            {
                byte[] hash = shaM.ComputeHash(Encoding.ASCII.GetBytes("Pair-Verify-AES-IV").Concat(Utils.Utils.HexStringToByteArray(shared)).ToArray());
                hash = hash.Skip(0).Take(16).ToArray();
                return Convert.ToHexString(hash);
            }
 
        }

        // ...
        // Public.

        public static string a_pub(byte[] a)
        {
            var ed = new Ed25519();
            ed.FromPrivateKey(a);
            return Convert.ToHexString(ed.GetPublicKey());
        }

        public static Dictionary<string,byte[]> confirm(byte[] a, string K)
        {
            string key = pair_setup_aes_key(K);
            string iv  = pair_setup_aes_iv(K);

            var plaintextBytes = Utils.Utils.HexStringToByteArray(a_pub(a));
            var ciphertext = new byte[Utils.Utils.HexStringToByteArray(a_pub(a)).Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            using (var aes = new AesGcm(Utils.Utils.HexStringToByteArray(key)))
            {
                aes.Encrypt(Utils.Utils.HexStringToByteArray(iv), plaintextBytes, ciphertext, tag);
            } ;

            Dictionary<string, byte[]> u = new Dictionary<string, byte[]>();
            u.Add("epk", ciphertext);
            u.Add("authTag", tag);
            return u;
        }

        public static Dictionary<string, byte[]> verifier(byte[] a)
        {
            var curve = new Curve25519();
            byte[] rndkey = new byte[32];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(rndkey);
            curve.FromPrivateKey(rndkey);
            byte[] v_pri = curve.GetPrivateKey();
            byte[] v_pub = curve.GetPublicKey();

            byte[] header = new byte[] {0x01, 0x00, 0x00, 0x00};
            byte[] a_pub_buf = Convert.FromHexString(a_pub(a));

            Dictionary<string, byte[]> u = new Dictionary<string, byte[]>();
            u.Add("verifierBody", header.Concat(curve.GetPublicKey()).Concat(a_pub_buf).ToArray());
            u.Add("v_pri", v_pri);
            u.Add("v_pub", v_pub);

            return u;
        }

        public static string shared(byte[] v_pri, byte[] atv_pub)
        {
            var curve = new Curve25519();
            curve.FromPublicKey(v_pri);           
            return Convert.ToHexString(curve.GetSharedSecret(atv_pub));
        }

    public static byte[] signed(byte[] a, byte[] v_pub, byte[] atv_pub)
    {
       var ed = new Ed25519();
       ed.FromPrivateKey(a);
       return ed.SignMessage(v_pub.Concat(atv_pub).ToArray());
    }
        
    public static byte[] signature(string shared, string atv_data, byte[] signed)
    {
            AesCtr aes = (AesCtr) AesCtr.Create();
            aes.Key = Utils.Utils.HexStringToByteArray(pair_verify_aes_key(shared));
            aes.IV = Utils.Utils.HexStringToByteArray(pair_verify_aes_iv(shared));
            aes.BlockSize = 128;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] result = new byte[0];
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                {
                    cs.Write(Convert.FromHexString(atv_data).Concat(signed).ToArray(), 0, atv_data.Length + signed.Length);
                }
                
                byte[] chunk = ms.ToArray();
                result = result.Concat(chunk).ToArray();
            }
        return result;
    }

        //module.exports = {
        //    pair_setup_aes_key,
        //    pair_setup_aes_iv,
        //    pair_verify_aes_key,
        //    pair_verify_aes_iv,

        //    a_pub,
        //    confirm,
        //    verifier,
        //    shared,
        //    signed,
        //    signature
        //};
    }
}
