using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Identity;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using System.Web;
using System;
using Microsoft.AspNetCore.Http;

namespace OppeniddictServer.Pages
{
    public class ServerLoginModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly ClientSeeder _seeder;

        public ServerLoginModel(UserManager<UserIdentity> userManager,
                                //IServiceProvider serviceProvider,
                                ClientSeeder seeder)
        {
            _userManager = userManager;
            _seeder = seeder;
        }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string Password { get; set; }

        [BindProperty]
        public string? ReturnUrl { get; set; }

        [BindProperty]
        public string RememberMe { get; set; }
        
        [BindProperty]
        public string Status { get; set; } 



        public async void OnGet()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        public async Task<IActionResult> OnPost(string client_id=null!)
        {
            if (client_id == null)
            {
                return await ServerLogin();
            }
                //var parameters = HttpContext.Request.QueryString;

                //string client_id = "";
                string queryString = ReturnUrl.Split('?')[1];
            var queryParams = queryString.Split('&');
 
            foreach (var param in queryParams)
            {
                var keyValue = param.Split('=');
                string key = keyValue[0];
                string value = keyValue[1];
                if (keyValue[0]=="client_id")
                {
                    client_id = keyValue[1];
                    break;
                }

            }

            var clientExist = await _seeder.CheckClient(client_id);
            if (clientExist == null)
            {
                //AuthStatus = "Parameter Mismatched or Invalid";
                return Page();
            }
            if (!ModelState.IsValid)
            {
                return Page();
            }

            /*var user = await _userManager.FindByNameAsync(Email)
                    ?? await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                //AuthStatus = "Cannot authenticate - No user found with above Credentials";
                return Page();
            }

            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
                    {
                        new (ClaimTypes.Email,Email),
                        new (ClaimTypes.Name,user.NormalizedUserName),
                        new (ClaimTypes.SerialNumber,user.Id!),
                    };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));

            }

            var principal = new ClaimsPrincipal(
                new List<ClaimsIdentity>
            {
                    new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme)
            });

            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);*/

            await ServerLogin();
            if (!string.IsNullOrEmpty(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }
            //AuthStatus = "Authentication-Success";
            return Page();
        }

        private async Task<IActionResult> ServerLogin()
        {
            var user = await _userManager.FindByNameAsync(Email)
                        ?? await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                Status = "Cannot authenticate - No user found with above Credentials";
                return Page();
            }

            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
                    {
                        new (ClaimTypes.Email,Email),
                        new (ClaimTypes.Name,user.NormalizedUserName),
                        new (ClaimTypes.SerialNumber,user.Id!),
                    };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));

            }

            var principal = new ClaimsPrincipal(
                new List<ClaimsIdentity>
            {
                    new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme)
            });

            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);
            return Redirect("~/Index");
        }
    }
}
