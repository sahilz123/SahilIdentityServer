using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OpenIddict.Abstractions;
using OppeniddictServer.Identity;
using OppeniddictServer.Model;
using OppeniddictServer.Openiddict;
using System.Data;

namespace OppeniddictServer.Pages
{
    public class ServerRegisterModel : PageModel
    {

        private readonly UserManager<UserIdentity> _userManager;

        //[BindProperty]
        //public string? FirstName { get; set; }

        //[BindProperty]
        //public string? LastName { get; set; }
        
        [BindProperty]
        public string Username { get; set; }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string Password { get; set; }

        [BindProperty]
        public string ConfirmPassword { get; set; }

        public List<UserIdentityRole> Roles { get; set; }


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
                               
                // Create the user
                var user = new UserIdentity
                {
                    UserName = Username,
                    Email = Email
                };

               var result= await _userManager.CreateAsync(user,Password);

                if (result.Succeeded)
                {
                   // await _scopeManager.CreateAsync(,Scope,);

                    await _userManager.AddToRoleAsync(user, "User");  //assigning default user role

                    return Redirect("/ServerLogin" + parameters);
                }

                if(result.Errors.Any())
                {
                    return Page();
                }
            }

            return Page();
        }
    }
}