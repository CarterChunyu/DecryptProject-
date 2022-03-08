using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RuitingHelper
{
    internal class RsaHelper
    {
        internal static bool VertifySignature(string xml_pubkey, string source, string signature)
        {
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xml_pubkey);
                byte[] sourceArray = Encoding.UTF8.GetBytes(source);
                byte[] signatureArray = Convert.FromBase64String(signature);
                bool flag = rsa.VerifyData(sourceArray, new SHA1CryptoServiceProvider(), signatureArray);
                return flag;
            }
            catch (Exception ex)
            {

            }
            return false;

        }

        internal static string Encrypte(string xml_pubkey, string source)
        {
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(xml_pubkey);
                byte[] sourceArray = Convert.FromBase64String(source);
                byte[] encryptArray = rsa.Encrypt(sourceArray, true);
                return Convert.ToBase64String(encryptArray);
            }
            catch (Exception ex)
            {
                return null;
            }
        }
    }
}
