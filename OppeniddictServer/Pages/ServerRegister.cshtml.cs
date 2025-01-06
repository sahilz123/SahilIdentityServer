using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.Identity;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace OppeniddictServer.Pages
{
    [AllowAnonymous]
    public class ServerRegisterModel : PageModel
    {

        private readonly UserManager<UserIdentity> _userManager;

       
        [BindProperty]
        [DataType(DataType.Text)]
        public string Username { get; set; }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string Password { get; set; }

        [BindProperty]
        public string ConfirmPassword { get; set; }

        [BindProperty]
        public string? ReturnUrl { get; set; }
        public string? Scope { get; set; }

        public ServerRegisterModel(UserManager<UserIdentity> userManager)
        {
            _userManager = userManager;
        }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost()
        {
            var parameters = HttpContext.Request.QueryString;

            if (Password != ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Passwords do not match.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                var isEmailTaken = await _userManager.FindByEmailAsync(Email);
                if (isEmailTaken != null)
                {
                    ModelState.AddModelError(string.Empty, "Email is already taken.");
                    return Page();
                }

                var user = new UserIdentity
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = Username,
                    Email = Email
                };

                var result = await _userManager.CreateAsync(user, Password);

                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");  //assigning default user role

                    return Redirect("/ServerLogin" + parameters);
                }

                if (result.Errors.Any())
                {
                    return Page();
                }
            }

            return Page();
        }
    }
}