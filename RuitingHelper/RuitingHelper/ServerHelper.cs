using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RuitingHelper
{
    public class ServerHelper : IServerHelper
    {
        public bool Vertify(string xml_pubkey, string source, string signature)
        {
            return RsaHelper.VertifySignature(xml_pubkey, source, signature);
        }
        public async Task<int> EncryptFile(Stream source, string savepath)
        {
            try
            {
                await AesHelper.Aes_Encrypt("ruiting", source, savepath);
            }
            catch (Exception ex)
            {
                return -1;
            }
            return 1;
        }

        public string GetAesKeyIv(string rsaPubkey)
        {
            byte[] aesKeyArray = AesHelper.Get_AesKeyIv("ruiting");
            string source = Convert.ToBase64String(aesKeyArray);
            string encresult = RsaHelper.Encrypte(rsaPubkey, source);
            return encresult;
        }

        public string InitialAesKey()  
        {
            try
            {
                AesHelper.CreateAesCng("ruiting");
                return "Success";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}
