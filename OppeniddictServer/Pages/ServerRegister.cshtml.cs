using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.Identity;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using OppeniddictServer.Constants;

namespace OppeniddictServer.Pages
{
    [AllowAnonymous]
    public class ServerRegisterModel : PageModel
    {

        private readonly UserManager<UserIdentity> _userManager;


        [BindProperty]
        [DataType(DataType.Text)]
        public string Username { get; set; } = default!;

        [BindProperty]
        public string Email { get; set; }= default!;

        [BindProperty]
        public string Password { get; set; }=default!;

        [BindProperty]
        public string ConfirmPassword { get; set; } = default!;

        [BindProperty]
        public string ReturnUrl { get; set; } = default!;
        public string Scope { get; set; } = default!;

        public ServerRegisterModel(UserManager<UserIdentity> userManager)
        {
            _userManager = userManager;
        }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost()
        {

            if (Password != ConfirmPassword)
            {
                ModelState.AddModelError(string.Empty,Register.PasswordsDoNotMatch );
                return Page();
            }

            if (ModelState.IsValid)
            {
                var isEmailTaken = await _userManager.FindByEmailAsync(Email);
                if (isEmailTaken != null)
                {
                    ModelState.AddModelError(string.Empty, Register.EmailAlreadyTaken);
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
                    var parameters = HttpContext.Request.QueryString;

                    await _userManager.AddToRoleAsync(user, Roles.User);  //assigning default user role

                    return Redirect(Urls.ServerLogin + parameters);
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