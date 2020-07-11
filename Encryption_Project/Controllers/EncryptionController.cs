namespace Encryption_Project.Controllers
{
    using Encryption_Project.Models;
    using Encryption_Project.Services;
    using Ionic.Zip;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading.Tasks;

    [ApiController]
    public class EncryptionController : ControllerBase
    {

        private readonly IEncryptionService _encryptionService;
        private readonly IWebHostEnvironment _environment;

        public EncryptionController(IEncryptionService encryptionService, IWebHostEnvironment environment)
        {
            _encryptionService = encryptionService;
            _environment = environment;
        }

        [HttpPost(ApiRoutes.Encryption.EncryptText)]
        public async Task<IActionResult> EncryptText([FromBody]EncryptData data)
        {
            if (string.IsNullOrEmpty(data.ClearText))
            {
                return BadRequest(new { Error = "Please enter a valid plain text" });
            }
            if (string.IsNullOrEmpty(data.PassPhrase))
            {
                return BadRequest(new { Error = "Please enter a valid Password" });
            }
            if (data.Iv.Length > 0 && data.Iv.Length != 16)
            {
                return BadRequest(new { Error = "Iv Size should be 16" });
            }
            if (data.KeySize != 128 && data.KeySize != 192 && data.KeySize != 256)
            {
                return BadRequest(new { Error = "make sure the key size is 128 or 192 or 256" });
            }
            string CipherText = await _encryptionService.EncryptTextAsync(data.ClearText, data.PassPhrase,data.KeySize,data.Iv);

            return Ok(new { Data = CipherText });
        }

        [HttpPost(ApiRoutes.Encryption.DecryptText)]
        public async Task<IActionResult> DecryptTextAsync([FromBody]EncryptData data)
        {
            if (string.IsNullOrEmpty(data.ClearText))
            {
                return BadRequest(new { Error = "Please enter a valid plain text" });
            }
            if (string.IsNullOrEmpty(data.PassPhrase))
            {
                return BadRequest(new { Error = "Please enter a valid Password" });
            }
            if (data.Iv.Length > 0 && data.Iv.Length != 16)
            {
                return BadRequest(new { Error = "Iv Size should be 16" });
            }
            if(data.KeySize != 128 && data.KeySize != 192 && data.KeySize != 256)
            {
                return BadRequest(new { Error = "make sure the key size is 128 or 192 or 256" });
            }
            string plainText = await _encryptionService.DecryptTextAsync(data.ClearText, data.PassPhrase, data.KeySize, data.Iv);

            return Ok(new { Data = plainText });
        }

        [HttpPost(ApiRoutes.Encryption.EncryptImages)]
        public async Task<IActionResult> EncryptImagesAsync([FromForm(Name = "ZipFile")] IFormFile zipFile)
        {

            MemoryStream fileStream = new MemoryStream();
            await zipFile.CopyToAsync(fileStream);
            fileStream.Seek(0, SeekOrigin.Begin);

            //using (ZipArchive archive = new ZipArchive(fileStream))
            //{
            //    archive.ExtractToDirectory(Path.Combine(_environment.WebRootPath,"Data/NormalImages"),true);
            //}
            ZipFile zip = ZipFile.Read(fileStream);
            Directory.Delete(Path.Combine(_environment.WebRootPath, "Data/NormalImages"), true);
            zip.ExtractAll(Path.Combine(_environment.WebRootPath, "Data/NormalImages"));

            var images = Directory.GetFiles(Path.Combine(_environment.WebRootPath, "Data/NormalImages/Encryption"));

            var EncryptedFolderpath = Path.Combine(_environment.WebRootPath, "Data/EncryptedImages");

            if (!Directory.Exists(EncryptedFolderpath))
            {
                Directory.CreateDirectory(EncryptedFolderpath);
            }
            int name = 1;
            foreach (var image in images)
            {
                byte[] cipherBytes = _encryptionService.Encrypt_Images(System.IO.File.ReadAllBytes(image));
                await System.IO.File.WriteAllBytesAsync(Path.Combine(EncryptedFolderpath,$"{name++}.png"), cipherBytes);
            }


            return Ok(new { Result ="Done"});
        }

        [HttpGet(ApiRoutes.Encryption.DownloadImages)]
        public IActionResult DownloadImages()
        {
            byte[] data = _encryptionService.DownloadImages();
            if (data == null)
            {
                return NotFound();
            }
            return File(data, "application/zip", $"test.zip");
        }

       

    }
}
