using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Encryption_Project.Models
{
    public class ApiRoutes
    {
        public const string Root = "api";

        public const string Version = "v1";

        public const string Base = Root + "/" + Version;

        public static class Encryption
        {
            public const string EncryptText = Base + "/Encryption/Encrypt/Text";

            public const string DecryptText = Base + "/Encryption/Decrypt/Text";

            public const string EncryptImages= Base + "/Encryption/Encrypt/Images";

            public const string DecryptImages = Base + "/Encryption/Encrypt/Images";

            public const string DownloadImages = Base + "/Encryption/Download";  
        }
    }
}
