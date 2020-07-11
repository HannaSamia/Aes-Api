using System;

namespace Encryption_Project.Services
{
    public interface IEncryptionService
    {
         System.Threading.Tasks.Task<string> EncryptTextAsync(string clearText, string PassPhrase, int KeySize, string Iv = null);
         System.Threading.Tasks.Task<string> DecryptTextAsync(string clearText, string PassPhrase, int KeySize, string Iv = null);
         byte[] Encrypt_Images(byte[] clearBytes);
         byte[] Dencryp_Images(byte[] clearBytes);

         Byte[] DownloadImages();
    }
}
