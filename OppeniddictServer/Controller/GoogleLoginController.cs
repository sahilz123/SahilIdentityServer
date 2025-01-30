using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace OppeniddictServer.Controller
{
    
    public class GoogleLoginController : Microsoft.AspNetCore.Mvc.Controller
    {
       
        [Route("GoogleLogin")]
        [AllowAnonymous]
        public async Task Login()
        {
            await HttpContext.ChallengeAsync(GoogleDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = Url.Action("GoogleResponse")
                });
        }

        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync("G"+CookieAuthenticationDefaults.AuthenticationScheme);

            var claims = result.Principal.Identities.FirstOrDefault().Claims.Select(claim => new
            {

                claim.Issuer,
                claim.OriginalIssuer,
                claim.Type,
                claim.Value
            });

            return Json(claims);
        }

    }
}
