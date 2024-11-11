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
                       //RedirectUri= "https://localhost:44310/Account/Register"
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
            // Retrieve the permanent authorizations associated with the user and the calling client application.
            /*var authorizations = await _authorizationManager.FindAsync(
                subject: Constants.Constants.Email,
                client: await _applicationManager.GetIdAsync(application),
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()).ToListAsync();

            switch (await _applicationManager.GetConsentTypeAsync(application))
            {
                // If the consent is external (e.g when authorizations are granted by a sysadmin),
                // immediately return an error if no authorization can be found in the database.
                case ConsentTypes.External when authorizations.Count is 0:
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "The logged in user is not allowed to access this client application."
                        }));

                // If the consent is implicit or if an authorization was found,
                // return an authorization response without displaying the consent form.
                case ConsentTypes.Implicit:
                case ConsentTypes.External when authorizations.Count is not 0:
                case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPrompt(Prompts.Consent):
                    // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                    var identity = new ClaimsIdentity(
                        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                        nameType: Claims.Name,
                        roleType: Claims.Role);

                    // Add the claims that will be persisted in the tokens.
                    identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                            .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                            .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
                            .SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user))
                            .SetClaims(Claims.Role, [.. (await _userManager.GetRolesAsync(user))]);

                    // Note: in this sample, the granted scopes match the requested scope
                    // but you may want to allow the user to uncheck specific scopes.
                    // For that, simply restrict the list of scopes before calling SetScopes.
                    identity.SetScopes(request.GetScopes());
                    identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

                    // Automatically create a permanent authorization to avoid requiring explicit consent
                    // for future authorization or token requests containing the same scopes.
                    var authorization = authorizations.LastOrDefault();
                    authorization ??= await _authorizationManager.CreateAsync(
                        identity: identity,
                        subject: await _userManager.GetUserIdAsync(user),
                        client: await _applicationManager.GetIdAsync(application),
                        type: AuthorizationTypes.Permanent,
                        scopes: identity.GetScopes());

                    identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                    identity.SetDestinations(GetDestinations);

                    return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // At this point, no authorization was found in the database and an error must be returned
                // if the client application specified prompt=none in the authorization request.
                case ConsentTypes.Explicit when request.HasPrompt(Prompts.None):
                case ConsentTypes.Systematic when request.HasPrompt(Prompts.None):
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "Interactive user consent is required."
                        }));

                // In every other case, render the consent form.
                default:
                    return View(new AuthorizeViewModel
                    {
                        ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                        Scope = request.Scope
                    });
            }
       */
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

        /*private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    // vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }
            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            

            return new LoginViewModel
            {
                AllowRememberLogin = false,
                EnableLocalLogin = false,
                ReturnUrl = returnUrl,
                Username = context!.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }*/

    
    }

}
