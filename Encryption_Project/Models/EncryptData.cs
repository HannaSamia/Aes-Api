using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Encryption_Project.Models
{
    public class EncryptData
    {
        public string ClearText { get; set; }
        public string PassPhrase { get; set; }
        public int KeySize { get; set; }
        public string Iv { get; set; }
}
}
