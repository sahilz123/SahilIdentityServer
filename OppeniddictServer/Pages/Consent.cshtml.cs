using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OppeniddictServer.Constants;
using System.Web;

namespace OppeniddictServer.Pages
{
    [Authorize]
    public class ConsentModel : PageModel
    {
        [BindProperty]
        public string? ReturnUrl { get; set; }
        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }


        public async Task<IActionResult> OnPostAsync(string grant)
        {
            if (grant != Constant.GrantAccessValue)
            {
                return Redirect(Urls.Error);
            }

            var consentclaim = User.GetClaim(Constant.ConsentNaming);

            if (string.IsNullOrEmpty(consentclaim))
            {
                User.SetClaim(Constant.ConsentNaming, grant);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User);
                await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, User);

            }

            return Redirect(ReturnUrl!);
        }
                
    }
}
