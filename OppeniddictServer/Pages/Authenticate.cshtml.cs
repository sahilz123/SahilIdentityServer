using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using OppeniddictServer.Interface;
using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using OppeniddictServer.ClientManager;
using System.Web;
using System;
using Microsoft.IdentityModel.Tokens;

namespace OppeniddictServer.Pages
{
    public class AuthenticateModel : PageModel
    {
        private readonly IClientService _clientService;
        public AuthenticateModel(IClientService clientService)
        {
            _clientService = clientService;
        }
        public string Email { get; set; } 
        public string Password { get; set; }
        [BindProperty]
        public string ReturnUrl { get; set; }
        public string AuthStatus { get; set; } = "UnAuthorized";

        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;

            var parameter = HttpUtility.ParseQueryString(returnUrl);
            Email = parameter.Get("email")!;
            Password = parameter.Get("password")!;


            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string email, string password)
        {
            //if(email.IsNullOrEmpty()|| password.IsNullOrEmpty()) throw new NoNullAllowedException();

            ClientData clientlist = await _clientService.GetClientList(email, password); //("No User Found -- Authorization Failed");
            if(clientlist==null)
            {
                AuthStatus = "Cannot authenticate - No user found with above Credentials";
                return Page();
            }
            //if client not authorize then redirect this page to signup that will add the client into database           

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email,email),
                new Claim(ClaimTypes.Role,clientlist.ClientRole.ToString()),
                new Claim(ClaimTypes.SerialNumber,clientlist.Client_Id!)
            };

            var principal = new ClaimsPrincipal(
                new List<ClaimsIdentity>
            {
                    new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme)
            });

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
            if (!string.IsNullOrEmpty(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }
            AuthStatus= "Authentication-Success";
            return Page();
        }

    }
}
