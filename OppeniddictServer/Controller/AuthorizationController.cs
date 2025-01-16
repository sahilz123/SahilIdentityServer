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
using Microsoft.AspNetCore.Identity;
using OppeniddictServer.Identity;
using Microsoft.AspNetCore.Authorization;
namespace OppeniddictServer.Controller
{
    [ApiController]
    public class AuthorizationController :Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthService _authService;

        private readonly UserManager<UserIdentity> _userManager;


        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager, 
            AuthService authService,
            UserManager<UserIdentity> userManager)

        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _authService = authService;

            _userManager = userManager;
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
                throw new InvalidOperationException(Error.OpenIdException);

            //var result1 =await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

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

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
                throw new InvalidOperationException(Error.ClientNotFound);

            var consentclaim = result.Principal!.GetClaim(Constants.Constant.ConsentNaming);

            if (consentclaim != Constant.GrantAccessValue)
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuilderRediect(HttpContext.Request, parameters));
                var consentRedirectUrl =Urls.ConsentWithReturnUrl+returnUrl;

                return Redirect(consentRedirectUrl);
            }

            var email = result.Principal!.FindFirst(ClaimTypes.Email)!.Value;

            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);


            var roles = result.Principal.FindAll(ClaimTypes.Role)       //have roleclaims binded within it
                                        .Select(r => r.Value)
                                        .ToImmutableArray();               
                     
           
            string _subject = result.Principal.FindFirst(ClaimTypes.Email)!.Value;
            var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, _subject)
                    .SetClaim(Claims.Email, email)
                    .SetClaims(Claims.Role, roles)
                    .SetClaim(Claims.PreferredUsername, user.UserName)
            ;

            foreach(var c in claims)
            {
                identity.SetClaim(c.Type,c.Value);
            }
            

            identity.SetScopes(request.GetScopes());

            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            string _client= await _applicationManager.GetIdAsync(application)?? throw new NullReferenceException();
             var authorizations = await _authorizationManager
                .FindAsync(   
                subject: _subject,
                client: _client,
                status:Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes()).ToListAsync();

            var authorization=authorizations.LastOrDefault();

            authorization ??= await _authorizationManager.CreateAsync(
                identity: identity,
                subject: _subject,
                client: _client, 
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes()) ;

            identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(AuthService.GetDestination);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            
        }

        [HttpPost("~/connect/token")]
        [AllowAnonymous]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException(Error.OpenIdException);

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException(Error.GrantTypeError);
            
            // Retrieve the claims principal stored in the authorization code/refresh token.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId!);

            var claims = result.Principal!.Claims.ToList();
                        
            var email = result.Principal.GetClaim(Claims.Email);              
            var id = result.Principal.GetClaim(Claims.ClientId);               
                                                                               
            var role = result.Principal.GetClaims(Claims.Role);                 
            var subject = result.Principal.GetClaim(Claims.Email);             
            var roleList = new List<string> { role.ToString()! }.ToImmutableArray();

            if (string.IsNullOrEmpty(email))
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = Error.TokenInvalid
                        }));
                }         

            var identity = new ClaimsIdentity(  result.Principal.Claims,
                                                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                                                nameType: Claims.Name,
                                                roleType: Claims.Role);

            // Override the user claims present in the principal in case they
            // changed since the authorization code/refresh token was issued.
            //identity.SetClaim(Claims.Subject, email)
            //        .SetClaim(Claims.Email, email)
            //        .SetClaim(Claims.Name, email)
            //        ;

            //foreach (var c in claims)
            //{
            //    identity.SetClaim(c.Type, c.Value);
            //}



            identity.SetDestinations(AuthService.GetDestination);

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
               return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        }

        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Urls.Home
                });
        }


    }

}
