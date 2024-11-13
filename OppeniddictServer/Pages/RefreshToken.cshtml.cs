using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace OppeniddictServer.Pages
{
    public class RefreshTokenModel : PageModel
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthService _authService;

        public string State { get; set; }


        public RefreshTokenModel(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager, AuthService authService)

        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _authService = authService;
        }
        public async void OnGet()
        {
            //using var client = _httpClientFactory.CreateClient();

            var parameter = _authService.ParseOAuthParameters(HttpContext);
            State = parameter["state"];

                      //var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var content = new FormUrlEncodedContent(new Dictionary<string, string> {

                { "grant_type", "refresh_token"},

                   {"client_id", "web-client" },
                   {"client_secret", "901564A5-E7FE-42CB-B10D-61EF6A8F3654"},
                    { "refresh_token", parameter["refresh"] }
            });

            //var response = await client.PostAsync("https://localhost:7000/connect/token",content );
            //await RefreshToken();
        }

        public async Task<IActionResult> RefreshToken()
        {
            var request = HttpContext.GetOpenIddictServerRequest();

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId);

            //await
            return Page();
        }
    }
}