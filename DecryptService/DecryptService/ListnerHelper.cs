using Spire.Doc;
using Spire.Doc.Documents;
using Spire.Pdf;
using Spire.Pdf.Graphics;
using Spire.Xls;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace DecryptService
{    
    public class ListnerHelper 
    {
        public void InitializeHttplistener(ref HttpListener httpListener)
        {
            httpListener.BeginGetContext(new AsyncCallback(OnRequestRecieve), httpListener);
        }

        private void OnRequestRecieve(IAsyncResult ar)
        {
            HttpListener httpListener = (HttpListener)ar.AsyncState;

            httpListener.BeginGetContext(OnRequestRecieve, httpListener);
            HttpListenerContext context = httpListener.EndGetContext(ar);

            try
            {
                string function = HttpUtility.UrlDecode(context.Request.QueryString["function"]);
                FunctionName name = (FunctionName)Enum.Parse(typeof(FunctionName), function, true);
                Common common = new Common();
                switch (name)
                {
                    case FunctionName.set_rsakey:
                        common.CommonFuc(context, common.SetRsaKey).Wait();
                        break;
                    case FunctionName.get_rsapubkey:
                        common.CommonFuc(context, common.GetRsaPubkey).Wait();
                        break;
                    case FunctionName.rsa_signature:
                        common.CommonFuc(context, common.Signature).Wait();
                        break;
                    case FunctionName.aes_decryptfile:
                        common.CommonFuc(context, common.Decryptfile).Wait();
                        break;
                }

            }
            catch (Exception ex)
            {
            }
        }
        public class Common
        {
            public async Task CommonFuc(HttpListenerContext context,
            Func<HttpListenerRequest, HttpListenerResponse, byte[]> func)
            {
                HttpListenerRequest request = context.Request;
                HttpListenerResponse response = context.Response;
                byte[] buffer = func.Invoke(request, response);
                response.ContentLength64 = buffer.Length;
                Stream output = response.OutputStream;
                await output.WriteAsync(buffer, 0, buffer.Length);
                await output.FlushAsync();
                output.Dispose();
                output.Close();
                response.Close();
            }

            public byte[] SetRsaKey(HttpListenerRequest request, HttpListenerResponse response)
            {
                string account = HttpUtility.UrlDecode(request.QueryString["account"]);
                string rsa_pubkey = RsaService.SetRsaKey(account); //產生RsaKeys
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*"); //RsaKeys
                response.ContentType = "application/json";
                response.ContentEncoding = Encoding.UTF8;
                byte[] buffer = Encoding.UTF8.GetBytes(rsa_pubkey);
                return buffer;
            }

            public byte[] GetRsaPubkey(HttpListenerRequest request, HttpListenerResponse response)
            {
                string account = HttpUtility.UrlDecode(request.QueryString["account"]);
                string rsa_pubkey = RsaService.GetRsaPubKey(account); 
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*"); 
                response.ContentType = "application/json";
                response.ContentEncoding = Encoding.UTF8;
                byte[] buffer = Encoding.UTF8.GetBytes(rsa_pubkey);
                return buffer;
            }
            public byte[] Signature(HttpListenerRequest request, HttpListenerResponse response)
            {
                string account = HttpUtility.UrlDecode(request.QueryString["account"]);
                string source = $"{account}{Guid.NewGuid()}";
                string signature = RsaService.Signature(source, account);
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*");
                response.Headers.Add("Access-Control-Expose-Headers", "*");
                response.Headers.Add("signature", signature);
                response.ContentType = "application/json";
                byte[] buffer = Encoding.UTF8.GetBytes(source);
                return buffer;
            }

            public byte[] Decryptfile(HttpListenerRequest request, HttpListenerResponse response)
            {
                try
                {
                    string account = HttpUtility.UrlDecode(request.QueryString["account"]);

                    string enc_aesKeyIv = request.QueryString["enc_aeskeyiv"];
                    string filename = HttpUtility.UrlDecode(request.QueryString["filename"]);
                    byte[] aesKeyIvArray = RsaService.RsaDecrypt(account, enc_aesKeyIv);
                    Stream stream = request.InputStream;
                    MemoryStream ms = new MemoryStream();
                    stream.CopyToAsync(ms).Wait();
                    string dir_path = Directory.CreateDirectory(Path.Combine
                        (Directory.GetCurrentDirectory(), Guid.NewGuid().ToString())).FullName;

                    string enc_path = Path.Combine(dir_path, "source.bin");
                    string dec_path = Path.Combine(dir_path, $"{filename}");
                    using (FileStream fs = new FileStream(enc_path, FileMode.Create, FileAccess.Write))
                    {
                        ms.WriteTo(fs);
                    }

                    AesService.AesDecrypteFile(aesKeyIvArray, enc_path, dec_path).Wait();
                    string text = $"{account} {HelperService.Get_ip4()}";
                    string watertfilepath = dec_path.Createwatermark(true, dir_path, text);
                    byte[] decArray = File.ReadAllBytes(watertfilepath);
                    Directory.Delete(dir_path, true);

                    response.StatusCode = 200;
                    response.Headers.Add("Access-Control-Allow-Origin", "*");
                    response.ContentType = "application/bson";
                    response.ContentLength64 = decArray.Length;
                    return decArray;
                }
                catch (Exception ex)
                {
                    return null;
                }
            }
        }
    }
    enum FunctionName
    {
        set_rsakey, get_rsapubkey, rsa_signature, aes_decryptfile
    }


    public class RsaService
    {
        public static string SetRsaKey(string account) 
        {
            CspParameters csp = new CspParameters()
            {
                KeyContainerName = account
            };
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
            string pubKey = rsa.ToXmlString(false);
            return pubKey;
        }
        public static string GetRsaPubKey(string account)
        {
            return SetRsaKey(account);
        }

        public static string Signature(string source, string account)
        {
            RSACryptoServiceProvider rsa = AdminGetRsaProvider(account);
            byte[] rawData = Encoding.UTF8.GetBytes(source);
            Stream stream = new MemoryStream(rawData);
            byte[] signature = rsa.SignData(stream, new SHA1CryptoServiceProvider());
            return Convert.ToBase64String(signature);
        }

        public static byte[] RsaDecrypt(string account, string source)
        {
            try
            {
                RSACryptoServiceProvider rsa = AdminGetRsaProvider(account);
                byte[] sourceArray = Convert.FromBase64String(source);
                return rsa.Decrypt(sourceArray, true);
            }
            catch (Exception ex)
            {
                return null;
            }

        }
        private static RSACryptoServiceProvider AdminGetRsaProvider(string keyContainerName)
        {
            CspParameters csp1 = new CspParameters()
            {
                KeyContainerName = keyContainerName
            };
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp1);
            return rsa;
        }
    }
    public class AesService
    {
        public static async Task<byte[]> AesDecrypteFile(byte[] aesKeyIvArray, string enc_path, string dec_path)
        {
            AesManaged aesManaged = GetAesManaged(aesKeyIvArray);
            try
            {
                using (FileStream sourcefs = new FileStream(enc_path, FileMode.Open, FileAccess.Read))
                {
                    using (CryptoStream decStream = new CryptoStream(sourcefs, aesManaged.CreateDecryptor(), CryptoStreamMode.Read))
                    {

                        using (FileStream fs = new FileStream(dec_path, FileMode.Create, FileAccess.Write))
                        {
                            byte[] buffer = new byte[65536];
                            int byteRead = 0;
                            while ((byteRead = await decStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                await fs.WriteAsync(buffer, 0, byteRead);
                            }                         
                        }
                        return File.ReadAllBytes(dec_path);
                    }
                }
            }
            catch (Exception ex)
            {

            }
            return null;
        }

        public static async Task<byte[]> AesDecrypteFile(byte[] aesKeyIvArray, Stream source)
        {
            AesManaged aesManaged = GetAesManaged(aesKeyIvArray);
            using (CryptoStream decsteam = new CryptoStream(source, aesManaged.CreateDecryptor(), CryptoStreamMode.Read))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    try
                    {
                        byte[] buffer = new byte[65536];
                        int byteRead = 0;
                        while ((byteRead = await decsteam.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await ms.WriteAsync(buffer, 0, buffer.Length);
                        }
                        return ms.ToArray();

                    }
                    catch (Exception ex)
                    {
                        return null;
                    }
                }
            }
        }
        private static AesManaged GetAesManaged(byte[] aesKeyIvArray)
        {
            AesManaged aes = new AesManaged()
            {
                KeySize = 256,
                Key = aesKeyIvArray.Take(32).ToArray(),
                IV = aesKeyIvArray.Skip(32).Take(16).ToArray(),
                BlockSize = 128
            };
            aes.IV = aesKeyIvArray.Skip(32).Take(16).ToArray();
            return aes;
        }
    }
    public static class HelperService
    {
        public static string Get_ip4()
        {
            string strHostName = Dns.GetHostName();
            IPHostEntry ipHostEntry = Dns.GetHostEntry(strHostName);
            IPAddress ipAddress = ipHostEntry.AddressList[1]; //第一個是IP6
            return ipAddress.ToString();
        }
        public static string Createwatermark(this string sourcefilepath, bool flag, string dir_path, string text)
        {
            if (!flag)
            {
                return sourcefilepath;
            }
            string source_extension = Path.GetExtension(sourcefilepath);
            string result_path = Path.Combine(dir_path, $"watermark{source_extension}");  //增加浮水印後圖片的路徑
            Format format = CheckFormat(source_extension);
            switch (format)
            {
                case Format.Pic:
                    sourcefilepath.ImgAddWatermark(result_path, text);
                    break;
                case Format.Excel:
                    sourcefilepath.ExcelAddWatermark(result_path, text);
                    break;
                case Format.Word:
                    sourcefilepath.WordAddWatermark(result_path, text);
                    break;
                case Format.Pdf:
                    sourcefilepath.PdfAddWatermark(result_path, text);
                    break;
                default:
                    result_path = sourcefilepath;
                    break;
            }
            return result_path;
        }
        private static Format CheckFormat(string extention)
        {
            Dictionary<List<string>, Format> dic = new Dictionary<List<string>, Format>()
            {
                {new List<string>(){ ".png",".jpg",".jpeg",".gif",".png" } ,Format.Pic},
                {new List<string>(){ ".pdf", } ,Format.Pdf},
                {new List<string>(){ ".xlsx" } ,Format.Excel},
                {new List<string>(){".docx"},Format.Word }
            };
            foreach (var key in dic.Keys)
            {
                if (key.Contains(extention))
                {
                    return dic[key];
                }
            }
            return Format.None;
        }
        private static void ImgAddWatermark(this string sourcefilepath, string outputfile_path, string text)
        {
            using (Bitmap bitmap = new Bitmap(sourcefilepath))
            {
                using (Graphics graphics = Graphics.FromImage(bitmap))
                {
                    Brush brush = new SolidBrush(Color.FromArgb(255, Color.Black)); 
                    System.Drawing.Font font = new System.Drawing.Font("Arial", 25, FontStyle.Regular, GraphicsUnit.Pixel); 
                    SizeF sizeF = graphics.MeasureString(text, font);
                    int horizontal_count = bitmap.Width / ((int)sizeF.Width * 2);
                    int vertical_count = bitmap.Height / ((int)sizeF.Height * 5);
                    for (int i = 0; i <= horizontal_count; i++)
                    {
                        for (int j = 0; j <= vertical_count; j++)
                        {
                            Point point = new Point(5 + ((int)sizeF.Width * 2) * i, 5 +
                                ((int)sizeF.Height * 5) * j);
                            graphics.DrawString(text, font, brush, point);
                        }
                    }
                    using (FileStream fs = new FileStream(outputfile_path, FileMode.Create, FileAccess.Write))
                    {
                        bitmap.Save(fs, ImageFormat.Jpeg);
                    }
                }
            }
        }
        private static void PdfAddWatermark(this string sourcefilepath, string outputfilepath, string text)
        {
            PdfDocument pdf = new PdfDocument();
            pdf.LoadFromFile(sourcefilepath);
            for (int i = 0; i < pdf.Pages.Count; i++)
            {
                PdfPageBase page = pdf.Pages[0];
                PdfTilingBrush brush = new PdfTilingBrush(new SizeF(page.Canvas.ClientSize.Width / 2, page.Canvas.ClientSize.Height / 6));
                brush.Graphics.SetTransparency(0.3f);
                brush.Graphics.Save();
                brush.Graphics.TranslateTransform(brush.Size.Width / 2, brush.Size.Height / 2);
                //brush.Graphics.RotateTransform(-45);
                brush.Graphics.DrawString(text, new PdfFont(PdfFontFamily.Helvetica, 24), PdfBrushes.Blue, 0, 0, new PdfStringFormat(PdfTextAlignment.Center));
                brush.Graphics.Restore();
                brush.Graphics.SetTransparency(1);
                page.Canvas.DrawRectangle(brush, new RectangleF(new PointF(0, 0), page.Canvas.ClientSize));
            }
            pdf.SaveToFile(outputfilepath);
        }

        private static void ExcelAddWatermark(this string sourcefilepath, string outputfile_path, string text)
        {
            Workbook workbook = new Workbook();
            workbook.LoadFromFile(sourcefilepath);

            System.Drawing.Font font = new System.Drawing.Font("宋體", 40);
            string watermark = text;

            foreach (Worksheet sheet in workbook.Worksheets)
            {

                System.Drawing.Image imgWtrmrk = DrawText(watermark, font, Color.LightCoral, Color.White, sheet.PageSetup.PageHeight, sheet.PageSetup.PageWidth);

                sheet.PageSetup.BackgoundImage = imgWtrmrk as Bitmap;
            }
            workbook.SaveToFile(outputfile_path, ExcelVersion.Version2016);
        }
        private static System.Drawing.Image DrawText(string text, System.Drawing.Font font, Color textColor, Color backColor,
            double height, double width)
        {
            System.Drawing.Image img = new Bitmap((int)width, (int)height);
            Graphics drawing = Graphics.FromImage(img);
            SizeF textSize = drawing.MeasureString(text, font);
            drawing.Clear(backColor);
            Brush textBrush = new SolidBrush(textColor);
            drawing.DrawString(text, font, textBrush, ((int)width - textSize.Width) / 2, ((int)height - textSize.Height) / 2);
            drawing.Save();
            return img;
        }

        private static void WordAddWatermark(this string sourcefilepath, string outputfile_path, string text)
        {
            Document doc = new Document();
            doc.LoadFromFile(sourcefilepath);
            TextWatermark txtWatermark = new TextWatermark();
            txtWatermark.Text = text;
            txtWatermark.FontSize = 30;
            txtWatermark.Layout = WatermarkLayout.Horizontal;
            doc.Watermark = txtWatermark;
            doc.SaveToFile(outputfile_path);
        }
    }
    enum Format
    {
        Pic, Word, Pdf, Excel, None
    }
}
