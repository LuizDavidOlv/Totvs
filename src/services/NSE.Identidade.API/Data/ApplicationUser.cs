using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NSE.Identidade.API.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }
        public string Perfil { get; set; }
        public string CreationDate { get; set; }
        public string LastModificationDate { get; set; }
        public string LastLoginDate { get; set; }
    }
}
