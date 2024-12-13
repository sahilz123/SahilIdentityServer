using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using OppeniddictServer.Identity;
using OpenIddict.Abstractions;
using System.Reflection;
using System.Text.Json;
using System.Collections.Immutable;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Model;
using NuGet.Protocol;

namespace OppeniddictServer.Pages
{
    public class AuthenticateModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly IServiceProvider _serviceProvider;
        private readonly ClientSeeder _seeder;


        public ClientDetails clientDetails { get; set; } = new ClientDetails();
        public AuthenticateModel(UserManager<UserIdentity> userManager, 
                                IServiceProvider serviceProvider,
                                ClientSeeder seeder)
                                
        {
            _userManager = userManager;
            _serviceProvider = serviceProvider;
            _seeder = seeder;
        }
        public string? Email { get; set; }
        public string? Password { get; set; }
        [BindProperty]
        public string? ReturnUrl { get; set; }        
        public string AuthStatus { get; set; } = "UnAuthorized";

        public IActionResult OnGet()
        {
      
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string email, string password, string client_id, string appScopes,string redirectUri)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            //var client = await manager.FindByClientIdAsync(client_id.ToString());

            var clientExist =await _seeder.CheckClient(client_id);
            if (clientExist==null)
            {
                AuthStatus = "Parameter Mismatched or Invalid";
                return Page();
            }
           
            var user = await _userManager.FindByNameAsync(email)
            ?? await _userManager.FindByEmailAsync(email);


            if (user==null)
            {
                AuthStatus = "Cannot authenticate - No user found with above Credentials";
                return Page();
            }
            //if client not authorize then redirect this page to RegisterInput that will add the client into database           

            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new (ClaimTypes.Email,email),
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
                    new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme)
            });
            
            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);
            
            if (!string.IsNullOrEmpty(ReturnUrl))
            {
                return Redirect(ReturnUrl);
            }
            AuthStatus= "Authentication-Success";
            return Page();
        }

/*        private async Task<bool> ClientDetailsExist(string client_id, string appScopes,string providedredirectUri)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (client_id == null)
                return false;
            try {

                var client = await manager.FindByClientIdAsync(client_id.ToString());              //fetch database for the client details , no seediing now

            if (client == null)
            {
                AuthStatus = "Client not found or response is invalid.";
                return false;
            }
            //var apiscope = await _scopeManager.FindByNameAsync(appScopes);

            Type myType = client!.GetType()!;
            IList<PropertyInfo> props = new List<PropertyInfo>(myType.GetProperties());
            foreach (PropertyInfo prop in props)
            {
                object propValue = prop!.GetValue(client, null)!;

                if (prop.Name == "ClientId")
                {
                    clientDetails.clientId = propValue!.ToString()!;
                }
                if (prop.Name == "RedirectUris")
                {
                    clientDetails.redirect_Uri = propValue!.ToString()!;
                }

                if (prop.Name == "State")
                {
                    clientDetails.state = propValue!.ToString()!;
                }
            }

            clientDetails.scopes= appScopes;
            clientDetails.ProvidedRedirectUri = providedredirectUri;
            ReturnUrl = clientDetails.returnUrl;
            }
            catch (Exception ex)
            {
                AuthStatus = ex.Message;
            }

            if (clientDetails.SelectedRedirectUri == null ||
                clientDetails.scopes == null ||
                clientDetails.clientId == null)
                return false;

            return true;

        }
*/    }

}
public class ClientDetails
{
    public string? clientId { get; set; }
    public string? redirect_Uri { get; set; }     //json form from the server databse
    public string? scopes { get; set; }
    public string? state { get; set; }
    public string? ProvidedRedirectUri { get; set; }

    public List<string>? ParsedRedirectUris =>
        !string.IsNullOrEmpty(redirect_Uri)
            ? JsonSerializer.Deserialize<List<string>>(redirect_Uri)
            : new List<string>();

    public string? SelectedRedirectUri =>
            ParsedRedirectUris?.FirstOrDefault(uri => uri.Equals(ProvidedRedirectUri, StringComparison.OrdinalIgnoreCase));

    public string returnUrl => $"/connect/authorize?response_type=code&client_id={clientId}&redirect_uri={SelectedRedirectUri}&scope={scopes}&state={state}";
}
