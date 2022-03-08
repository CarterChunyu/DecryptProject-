using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RuitingHelper
{
    internal class AesHelper
    {
        private static readonly string iv_Str = "gFNNdlzLojwdYVbLbuzjaQ==";
        internal static bool isAesCngExisted(string keyName)
        {
            return CngKey.Exists(keyName);
        }
        internal static void DeleteAesCng(string keyName)
        {
            if (CngKey.Exists(keyName))
            {
                CngKey cngKey = CngKey.Open(keyName);
                cngKey.Delete();
            }
        }

        internal static void CreateAesCng(string keyName)
        {
            if (!CngKey.Exists(keyName))
            {
                CngAlgorithm cngAlgorithm = new CngAlgorithm("AES");
                CngProvider cngProvider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
                CngKeyCreationParameters cngKeyCreationParameters = new CngKeyCreationParameters()
                {
                    Provider = cngProvider,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                };
                CngKey cngKey = CngKey.Create(cngAlgorithm, keyName, cngKeyCreationParameters);
                AesCng aesCng = new AesCng(keyName);
            }
        }

        internal static byte[] Get_AesKeyIv(string keyName)
        {
            if (CngKey.Exists(keyName))
            {
                try
                {
                    AesCng aesCng = new AesCng(keyName);
                    byte[] aesKeyIv = aesCng.Key.Concat(Convert.FromBase64String(iv_Str)).ToArray();
                    return aesKeyIv;
                }
                catch (Exception ex) { }
            }
            return null;
        }
        internal static async Task<byte[]> Aes_Encrypt(string keyName, Stream sourceStream, string path)
        {
            try
            {
                if (sourceStream.Length > 0 && isAesCngExisted(keyName))
                {
                    AesCng aesCng = new AesCng(keyName);
                    aesCng.IV = Convert.FromBase64String(iv_Str);

                    using (FileStream encStream = new FileStream(path, FileMode.Create, FileAccess.Write))
                    {
                        using (CryptoStream outStream = new CryptoStream
                            (encStream, aesCng.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            byte[] buff = new byte[65536];
                            int Readbytes = 0;
                            while ((Readbytes = await sourceStream.ReadAsync(buff, 0, buff.Length)) > 0)
                            {
                                outStream.Write(buff, 0, Readbytes);
                            }

                        }
                    }
                    return File.ReadAllBytes(path);
                }
            }
            catch (Exception ex) { }
            return null;
        }

  
    }
}