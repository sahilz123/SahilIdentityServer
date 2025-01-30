using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Facebook;

namespace OppeniddictServer.Controller
{
    public class FacebookLoginController: Microsoft.AspNetCore.Mvc.Controller
    {
        [Route("FacebookLogin")]
        [AllowAnonymous]
        public async Task Login()
        {
            var fb = new FacebookClient();
            var loginUrl = fb.GetLoginUrl(new
            {
                client_id="",
                redirect_uri="",
                scope=""
            });

            ViewBag.Url=loginUrl;
        }

        [Route("FacebookRedirect")]
        public async Task<IActionResult> FacebookRedirect(string code)
        {
            var fb = new FacebookClient();
            dynamic result = fb.Get("/oauth/access_token", new
            {
                client_id = "",
                client_secret = "",
                redirect_uri = "",
                code = code
            });

            fb.AccessToken = result.AccessToken;

            dynamic me = fb.Get("/me?fields=name,email");
            string name = me.name;
            string email=me.email;
            return RedirectToAction("Index");
        }

    }
}
