using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Identity;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Authorization;
using OppeniddictServer.Constants;

namespace OppeniddictServer.Pages
{
    /// <summary>
    /// Entry point into the login workflow
    /// </summary>
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
        public string? Password { get; set; }

        [BindProperty]
        public string? ReturnUrl { get; set; }

        [BindProperty]
        public bool RememberMe { get; set; } 

        [BindProperty]
        public string? Status { get; set; }

        [BindProperty]
        [ValidateNever]
        public string? Client_Id { get; set; } = default!;



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

                Client_Id = queryParams
                .Select(param => param.Split('='))
                .FirstOrDefault(keyValue => keyValue[0] == "client_id")?[1];

                
                var clientExist = await _seeder.CheckClient(Client_Id!);        //must check that Client must exist before going ahead
                if (clientExist == null)
                {
                    Status = Error.ParameterError;
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
                Status = Error.AuthenticateError;
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
                    new (claims,CookieAuthenticationDefaults.AuthenticationScheme)
            });

            //await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);
            PasswordHasher<UserIdentity> _passwordHasher = new();
            var isPasswordValid = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, Password);
            if (isPasswordValid.ToString() == Error.StatusFailed)
            {
                Status = Error.PasswordMismatched;
                return Page();
            }

            var response = await _signInManager.PasswordSignInAsync(user, Password, RememberMe, false);
            if (!response.Succeeded)
            {
                Status = Error.InvalidCredential;
                return Page();
            }
            if (!string.IsNullOrEmpty(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }
            else
            {
                return Redirect(Urls.Index);
            }
        }
    }
}
