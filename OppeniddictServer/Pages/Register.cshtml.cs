using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Identity;
using System.Linq;

namespace OppeniddictServer.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly SignInManager<UserIdentity> _signInManager;
        private readonly RoleManager<UserIdentityRole> _roleManager;


        [BindProperty]
        public RegisterViewModel RegisterInput { get; set; } = new RegisterViewModel();

        public List<SelectListItem> Roles { get; set; } = new List<SelectListItem>();

        public string? ResponseMessage { get; set; }

        public RegisterModel(UserManager<UserIdentity> userManager, SignInManager<UserIdentity> signInManager,
            RoleManager<UserIdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        public void OnGet()
        {
            // Populate available roles for the dropdown
            Roles = _roleManager.Roles
                            .Select(role => new SelectListItem { Value = role.Name, Text = role.Name })
                            .ToList();
        }

        public async Task<IActionResult> OnPostAsync()//string client_id, string appScopes, string redirectUri)
        {
            var parameters = HttpContext.Request.QueryString;

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Check if the email is already taken
            var isEmailTaken = await _userManager.FindByEmailAsync(RegisterInput.Email);
            if (isEmailTaken != null)
            {
                ResponseMessage = "Email is already taken.";
                return Page();
            }

            // Create the user
            var user = new UserIdentity
            {
                UserName = RegisterInput.UserName,
                Email = RegisterInput.Email
            };

            var result = await _userManager.CreateAsync(user, RegisterInput.Password);

            if (result.Succeeded)
            {
                // Assign roles to the user
                foreach (var role in RegisterInput.Roles)
                {
                    if (!await _roleManager.RoleExistsAsync(role))
                    {
                        ModelState.AddModelError(string.Empty, $"Role '{role}' does not exist.");
                        return Page();
                    }

                    var roleResult = await _userManager.AddToRoleAsync(user, role);
                    if (!roleResult.Succeeded)
                    {
                        ResponseMessage = $"Failed to assign role: {role}";
                        return Page();
                    }
                }

                // Sign in the user after successful registration
                await _signInManager.SignInAsync(user, isPersistent: false);
                ResponseMessage = "Registration successful!";

                //return Challenge(
                //   authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                //  properties: new AuthenticationProperties
                //  {
                //      RedirectUri = "/Authenticate"+parameters
                //  });
                return Redirect("/Authenticate" + parameters); // Redirect to a success page or desired endpoint
            }

            // Handle errors from user creation
            foreach (var error in result.Errors)
            {
                ResponseMessage = error.Code.ToString();
                ResponseMessage = error.Description.ToString();
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }

    public class RegisterViewModel
    {
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new List<string>();
    }
}
