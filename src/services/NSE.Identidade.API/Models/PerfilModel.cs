using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NSE.Identidade.API.Models
{
    public class PerfilRequest
    {
        public string Email { get; set; }
        public string Perfil { get; set; }
    }

    public class PerfilResponse
    {
        public string Email { get; set; }
        public string Perfil { get; set; }
    }
}
