using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using System;
using System.Diagnostics.Eventing.Reader;
using System.Web;
using static System.Net.WebRequestMethods;

namespace OppeniddictServer.Pages
{
    [Authorize]
    public class ConsentModel : PageModel
    {
        [BindProperty]
        public string?  ReturnUrl { get; set; }
        public IActionResult OnGet(string returnUrl)
        {
            ReturnUrl = returnUrl;
            return Page();
        }


        public async Task<IActionResult> OnPostAsync(string grant) 
        {
            if (grant != Constants.Constants.GrantAccessValue)
            {
               return Redirect("/Error");
            }

            var consentclaim=User.GetClaim(Constants.Constants.ConsentNaming);

            if (string.IsNullOrEmpty(consentclaim) )
            {
                User.SetClaim(Constants.Constants.ConsentNaming, grant);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, User);
            }            

            return Redirect(ReturnUrl!);
        }

        private string parseurl(string url)
        {
            // Parse the URL
            UriBuilder uriBuilder = new UriBuilder("https://localhost:7000" + url);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);

            // Get the redirect_uri value
            string currentstate = query.Get("currentState")!;

            // Replace the currentState value with the redirect_uri value
            if (!string.IsNullOrEmpty(currentstate))
            {
                query.Set("redirect_uri", currentstate);
            }

            // Update the query string in the URI
            uriBuilder.Query = query.ToString();
            string updatedUrl = uriBuilder.ToString();
            return updatedUrl;
        }

    }
}
