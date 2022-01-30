using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSE.Identidade.API.Data;
using NSE.Identidade.API.Models;
using NSE.WebApi.Core.Controllers;
using NSE.WebApi.Core.Identidade;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using static NSE.Identidade.API.Models.UserViewModels;

namespace NSE.Identidade.API.Controllers
{

    [Route("api/identidade")]
    public class AuthController : MainController
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AppSettings _appSettings;

        public AuthController(SignInManager<ApplicationUser> signInManager,
                              UserManager<ApplicationUser> userManager,
                              IOptions<AppSettings> appSettings)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _appSettings = appSettings.Value;
        }

        [HttpPost("nova-conta")]
        public async Task<ActionResult> Registrar(UsuarioRegistro usuarioRegistro)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var user = new ApplicationUser
            {
                FullName = usuarioRegistro.Nome,
                UserName = usuarioRegistro.Email,
                Email = usuarioRegistro.Email,
                EmailConfirmed = true,
                Perfil = usuarioRegistro.Perfil,
                CreationDate = (DateTime.Now).ToString(),
                LastModificationDate = (DateTime.Now).ToString(),
                LastLoginDate = (DateTime.Now).ToString()
            };

            var result = await _userManager.CreateAsync(user, usuarioRegistro.Senha);

            if (result.Succeeded)
            {
                return CustomResponse(await CadastroResponse(usuarioRegistro.Email));
            }

            foreach (var error in result.Errors)
            {
                AdicionarErroProcessamento(error.Description);
            }
            return CustomResponse();
        }

        [HttpPost("autenticar")]
        public async Task<ActionResult> Login(UsuarioLogin usuarioLogin)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var result = await _signInManager.PasswordSignInAsync(usuarioLogin.Email, usuarioLogin.Senha, false, true);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(usuarioLogin.Email);
                user.LastLoginDate = (DateTime.Now).ToString();

                var update = await _userManager.UpdateAsync(user);

                return CustomResponse(GerarJwt(user));
            }

            if (result.IsLockedOut)
            {
                AdicionarErroProcessamento("Usuário temporariamente bloqueado por tentativas inválidas");
                return CustomResponse();
            }

            AdicionarErroProcessamento("Usuário ou senha inváldos");
            return CustomResponse();
        }

        [HttpGet("listar-perfil")]
        public async Task<ActionResult> ListarPerfil(string email)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);


            var user = await _userManager.FindByEmailAsync(email);

            if(user != null)
            {
                return CustomResponse(ListarPerfilUsuario(user));
            }

            AdicionarErroProcessamento("Usuário não encontrado.");
            return CustomResponse();
        }

        [HttpPut("inserir-perfil")]
        public async Task<ActionResult> InserirPerfil(PerfilRequest request)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user != null)
            {
                if (!user.Perfil.ToLower().Contains(request.Perfil.ToLower().Trim()))
                {
                    user.Perfil = user.Perfil + "," + request.Perfil;
                    var update = await _userManager.UpdateAsync(user);
                    if (update.Succeeded)
                    {
                        return CustomResponse(ListarPerfilUsuario(user));
                    }
                    else
                    {
                        AdicionarErroProcessamento("Não foi possível persistir perfil no banco.");
                    }
                }
                else
                {
                    AdicionarErroProcessamento("Usuário já possui o determinado perfil.");
                }
            }
            else
            {
                AdicionarErroProcessamento("Usuário não identificado!");
            }
            

            return CustomResponse();
        }









        private string CodificarToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _appSettings.Emissor,
                Audience = _appSettings.ValidoEm,
                Expires = DateTime.UtcNow.AddHours(_appSettings.ExpiracaoHoras),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            });

            return tokenHandler.WriteToken(token);
        }

        private UsuarioRespostaLogin ObterRespostaToken(string encodedToken, ApplicationUser user)
        {
            return new UsuarioRespostaLogin
            {
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(_appSettings.ExpiracaoHoras).TotalSeconds,
                UsuarioToken = new UsuarioToken
                {
                    Id = user.Id,
                    Email = user.Email

                }
            };
        }

        private UsuarioRespostaLogin GerarJwt(ApplicationUser user)
        {
            var encodedToken = CodificarToken();

            return ObterRespostaToken(encodedToken, user);
        }


        private UsuarioRespostaCadastro PopularReponseCadastro(ApplicationUser user)
        {
            return new UsuarioRespostaCadastro
            {
                Id = user.Id,
                Email = user.Email,
                CreationDate = user.CreationDate,
                LastModificationDate = user.LastModificationDate,
                LastLoginDate = user.LastLoginDate,
                Perfil = user.Perfil
            };
        }


        private async Task<UsuarioRespostaCadastro> CadastroResponse(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);


            return PopularReponseCadastro(user);
        }

        private ListarPerfilUsuario ListarPerfilUsuario(ApplicationUser user)
        {
            return new ListarPerfilUsuario
            {
                Id = user.Id,
                Email = user.Email,
                Perfil = user.Perfil
            };
        }

    }
}
