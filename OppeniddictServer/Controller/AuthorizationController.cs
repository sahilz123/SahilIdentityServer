using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Web;
using System.Collections.Immutable;
using OppeniddictServer.Constants;
namespace OppeniddictServer.Controller
{
    [ApiController]
    public class AuthorizationController :Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthService _authService;


        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager, AuthService authService)

        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _authService = authService;
        }

        ///// <summary>
        ///// Entry point into the login workflow
        ///// </summary>
        //[HttpGet("Login")]
        //[AllowAnonymous]
        //public async Task<IActionResult> Login(string returnUrl)
        //{
        //    // build a model so we know what to show on the login page
        //    var vm = await BuildLoginViewModelAsync(returnUrl);

        //    //if (vm.EnableLocalLogin == false && vm.ExternalProviders.Count() == 1)
        //    //{
        //    //    // only one option for logging in
        //    //    return ExternalLogin(vm.ExternalProviders.First().AuthenticationScheme, returnUrl);
        //    //}

        //    return View(vm);
        //}

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var result=await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var isAuthenticated=_authService.IsAuthenticated(result, request);

            var parameters = _authService.ParseOAuthParameters(HttpContext);
            if (!isAuthenticated)
            {
                return Challenge(
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                   properties: new AuthenticationProperties
                   {
                       RedirectUri = _authService.BuilderRediect(HttpContext.Request,parameters)
                   });
            }

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var consentclaim = result.Principal.GetClaim(Constants.Constants.ConsentNaming);

            if (consentclaim != Constants.Constants.GrantAccessValue)
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuilderRediect(HttpContext.Request, parameters));
                var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
            }
            


            var email = result.Principal.FindFirst(ClaimTypes.Email)!.Value;                     //check for roles from db and adjust claims
           // var id = result.Principal.FindFirst(ClaimTypes.SerialNumber)!.Value;               //check for id from db and adjust claims
           // var cookiepath = result.Principal.FindFirst(ClaimTypes.CookiePath)!.Value;         //check for path from db and adjust claims
            var role = result.Principal.FindFirst(ClaimTypes.Role)!.Value;                       //check for roles from db and adjust claims
            var subject = result.Principal.FindFirst(ClaimTypes.Email)!.Value;                   //check for subject from db and adjust claims
            var roleList = new List<string> {role.ToString() }.ToImmutableArray();

            var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, subject)
                    .SetClaim(Claims.Email, email)
                    .SetClaims(Claims.Role, roleList);
            

            identity.SetScopes(request.GetScopes());

            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

             var authorizations = await _authorizationManager
                .FindAsync(   
                subject: subject,
                client: await _applicationManager.GetIdAsync(application),
                status:Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes()).ToListAsync();

            var authorization=authorizations.LastOrDefault();

            authorization ??= await _authorizationManager.CreateAsync(
                identity: identity,
                subject: subject,
                client: await _applicationManager.GetIdAsync(application), 
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes()) ;

            identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(AuthService.GetDestination);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");
            
            // Retrieve the claims principal stored in the authorization code/refresh token.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId);

// Log the claims
            var claims = result.Principal!.Claims.ToList();

            var email = result.Principal.GetClaim(Claims.Email);               //check for roles from db and adjust claims
            var id = result.Principal.GetClaim(Claims.ClientId);               //check for id from db and adjust claims
                                                                               //var cookiepath = result.Principal.FindFirst(ClaimTypes.CookiePath)!.Value;               //check for path from db and adjust claims
            var role = result.Principal.GetClaim(Claims.Role);                 //check for roles from db and adjust claims
            var subject = result.Principal.GetClaim(Claims.Email);             //check for subject from db and adjust claims
            var roleList = new List<string> { role.ToString() }.ToImmutableArray();

            if (string.IsNullOrEmpty(email))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
                        }));
                }         

            var identity = new ClaimsIdentity(  result.Principal.Claims,
                                                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                                                nameType: Claims.Name,
                                                roleType: Claims.Role);

            // Override the user claims present in the principal in case they
            // changed since the authorization code/refresh token was issued.
            identity.SetClaim(Claims.Subject, email)
                    .SetClaim(Claims.Email, email)
                    .SetClaim(Claims.Name, email);
                    
        

            identity.SetDestinations(AuthService.GetDestination);

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
               return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        }

        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }

    
    }

}
