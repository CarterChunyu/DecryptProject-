using System.IO;
using System.Threading.Tasks;

namespace RuitingHelper
{
    public interface IServerHelper
    {
        Task<int> EncryptFile(Stream source, string savepath);
        string GetAesKeyIv(string rsaPubkey);
        string InitialAesKey();
        bool Vertify(string xml_pubkey, string source, string signature);
    }
}