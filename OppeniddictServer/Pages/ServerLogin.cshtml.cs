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
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.AspNetCore.Authorization;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace OppeniddictServer.Pages
{
    [AllowAnonymous]
    public class ServerLoginModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly ClientSeeder _seeder;
        private readonly SignInManager<UserIdentity> _signInManager;

        public ServerLoginModel(UserManager<UserIdentity> userManager,
                                ClientSeeder seeder,
                                SignInManager<UserIdentity> signInManager)
        {
            _userManager = userManager;
            _seeder = seeder;
            _signInManager = signInManager;
        }

        [BindProperty]
        [EmailAddress]
        public string? Email { get; set; }

        [BindProperty]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        [BindProperty]
        public string? ReturnUrl { get; set; }

        [BindProperty]
        public bool RememberMe { get; set; } 

        [BindProperty]
        public string? Status { get; set; }

        [BindProperty]
        [ValidateNever]
        public string? Client_Id { get; set; } = "";



        public  void OnGet()
        {
        }

        public async Task<IActionResult> OnPost()
        {
            if (!ModelState.IsValid)
            {               
                return Page();
            }

            if (ReturnUrl is not null && ReturnUrl.Contains("client_id"))           //login via application && initialize client id
            {
                string queryString = ReturnUrl.Split('?')[1];
                var queryParams = queryString.Split('&');

                foreach (var param in queryParams)
                {
                    var keyValue = param.Split('=');

                    if (keyValue[0] == "client_id")
                    {
                        Client_Id = keyValue[1];
                        break;
                    }

                }

                var clientExist = await _seeder.CheckClient(Client_Id!);
                if (clientExist == null)
                {
                    Status = "Parameter Mismatched or Invalid";
                    return Page();
                }

                return await ServerLogin();
            }
            else
            {
                return await ServerLogin();                                                //login to server directly
            }

           
        }

        /// <summary>
        /// check Credentials,Get required roles, Set Claims in the HttpContext
        /// Redirect to Server Dashboard or the Return Url
        /// </summary>
        /// <returns></returns>
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
                        new (ClaimTypes.Email,Email!),
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

            //await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);
            PasswordHasher<UserIdentity> _passwordHasher = new();
            var isPasswordValid = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, Password);
            if (isPasswordValid.ToString() == "Failed")
            {
                Status = "Password Mismatched";
                return Page();
            }

            var response =await _signInManager.PasswordSignInAsync(user,Password,RememberMe,false);
            if (!response.Succeeded)              
            {
                Status = "Invalid Credentials!!!";
                return Page();
            }
            if (!string.IsNullOrEmpty(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }
            else
            {
                return Redirect("~/Index");
            }
        }
    }
}
