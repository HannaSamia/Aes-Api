namespace Encryption_Project.Services
{
    using Ionic.Zip;
    using Microsoft.AspNetCore.Hosting;
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    public class EncryptionService : IEncryptionService
    {
        private readonly IWebHostEnvironment _environment;

        public EncryptionService(IWebHostEnvironment environment)
        {
            _environment = environment;
        }

        public async System.Threading.Tasks.Task<string> EncryptTextAsync(string clearText,string PassPhrase,int KeySize,string Iv = null)
        {
            byte[] saltStringBytes = GenerateSaltBitsOfRandomEntropy(KeySize / 8);
            byte[] ivStringBytes = new byte[16];

            if (!String.IsNullOrEmpty(Iv))
            {
                ivStringBytes = Encoding.UTF8.GetBytes(Iv);
            }

            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(PassPhrase, saltStringBytes, 100);
                encryptor.Key = pdb.GetBytes(KeySize / 8);
                encryptor.IV = ivStringBytes;
                encryptor.Mode = CipherMode.CBC;
                encryptor.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        await cs.WriteAsync(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    byte[] cipherTextBytes = saltStringBytes;
                    cipherTextBytes = cipherTextBytes.Concat(ms.ToArray()).ToArray();
                    clearText = Convert.ToBase64String(cipherTextBytes);
                }
            }
            return clearText;
        }

        public async System.Threading.Tasks.Task<string> DecryptTextAsync(string clearText, string PassPhrase, int KeySize, string Iv = null)
        {
            byte[] cipherTextBytesWithSaltAndIv = Convert.FromBase64String(clearText);
            byte[] saltStringBytes = cipherTextBytesWithSaltAndIv.Take(KeySize / 8).ToArray(); 
            byte[] cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip(KeySize / 8).Take(cipherTextBytesWithSaltAndIv.Length - (KeySize / 8)).ToArray(); 
            
            byte[] ivStringBytes = new byte[16];

            if (!String.IsNullOrEmpty(Iv))
            {
                ivStringBytes = Encoding.UTF8.GetBytes(Iv);
            }
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(PassPhrase, saltStringBytes,100);
                encryptor.Key = pdb.GetBytes(KeySize / 8);
                encryptor.IV = ivStringBytes;
                encryptor.Mode = CipherMode.CBC;
                encryptor.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        await cs.WriteAsync(cipherTextBytes, 0, cipherTextBytes.Length);
                        cs.Close();
                    }
                    clearText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return clearText;
        }

        public byte[] Encrypt_Images(byte[] clearBytes)
        {
            int keysize = 128;

            byte[] saltStringBytes = GenerateSaltBitsOfRandomEntropy(keysize/8);
            byte[] ivStringBytes = GenerateIVBitsOfRandomEntropy(keysize / 8);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes("124ko2l5a5r83aya6mar&i@o&cGhSa$%rb%e*lmaTfi8ay#rkoGnlAa7yfFouTftAFoychoFAufo0!u", saltStringBytes, 200);
                encryptor.Key = pdb.GetBytes(keysize / 8);
                encryptor.IV = ivStringBytes;
                encryptor.Mode = CipherMode.CBC;
                encryptor.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    byte[] cipherImageBytes = saltStringBytes;//Adding Salt to the beginning of the byte array
                    cipherImageBytes = cipherImageBytes.Concat(ivStringBytes).ToArray();//Adding IV key after the Salt key at the beginning of the byte array
                    cipherImageBytes = cipherImageBytes.Concat(ms.ToArray()).ToArray();////Adding the image bytes after the keys the beginning of the byte array
                    clearBytes = cipherImageBytes;
                }
            }
            return clearBytes;
        }

        public byte[] Dencryp_Images(byte[] clearBytes)
        {
            int keysize = 128;
            byte[] cipherTextBytesWithSaltAndIv = clearBytes;
            byte[] saltStringBytes = cipherTextBytesWithSaltAndIv.Take(keysize/8).ToArray(); //Extracting the Salt key from the begening of the image bytes array
            byte[] ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(keysize/8).Take(keysize/8).ToArray(); //Extracting the IV key
            byte[] cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip(keysize/8 + keysize/8).Take(cipherTextBytesWithSaltAndIv.Length - (keysize/8 + keysize/8)).ToArray(); //Extracting the image array without the keys

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes("124ko2l5a5r83aya6mar&i@o&cGhSa$%rb%e*lmaTfi8ay#rkoGnlAa7yfFouTftAFoychoFAufo0!u", saltStringBytes, 200);
                encryptor.Key = pdb.GetBytes(keysize / 8);
                encryptor.IV = ivStringBytes;
                encryptor.Mode = CipherMode.CBC;
                encryptor.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherTextBytes, 0, cipherTextBytes.Length);
                        cs.Close();
                    }
                    clearBytes = ms.ToArray();
                }
            }
            return clearBytes;
        }

        private byte[] GenerateSaltBitsOfRandomEntropy(int SaltKeysize)
        {
            byte[] randomBytes = new byte[SaltKeysize]; 
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        private byte[] GenerateIVBitsOfRandomEntropy(int IVKeysize)
        {
            byte[] randomBytes = new byte[IVKeysize]; // 16 Bytes will give us 128 bits.
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        public  Byte[] DownloadImages()
        {
            var EncryptedFolderpath = Path.Combine(_environment.WebRootPath, "Data/EncryptedImages");
            if (!Directory.Exists(EncryptedFolderpath))
            {
                return null;
            }
            using ZipFile zip = new ZipFile();
            zip.AddDirectory(EncryptedFolderpath);
            MemoryStream output = new MemoryStream();
            zip.Save(output);
            return output.ToArray();
        }

    }
}
