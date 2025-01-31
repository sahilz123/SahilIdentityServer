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
using Microsoft.Extensions.Primitives;
using System.Data;
using static System.Net.Mime.MediaTypeNames;
using System.Security.Principal;
using System.Net;
namespace OppeniddictServer.Controller
{
    [ApiController]
    public class AuthorizationController : Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly RoleManager<UserIdentityRole> _roleManager;
        private readonly AuthService _authService;

        private readonly UserManager<UserIdentity> _userManager;


        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager,
            IOpenIddictScopeManager scopeManager,
            AuthService authService,
            UserManager<UserIdentity> userManager,
            RoleManager<UserIdentityRole> roleManager
            )

        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _authService = authService;

            _userManager = userManager;
            _roleManager = roleManager;
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

            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            var isAuthenticated = _authService.IsAuthenticated(result, request);


            var parameters = _authService.ParseOAuthParameters(HttpContext);
            if (isAuthenticated is false)
            {
                return Challenge(
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                   properties: new AuthenticationProperties
                   {
                       RedirectUri = _authService.BuilderRediect(HttpContext.Request, parameters)
                   });
            }
            else
            {
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
                                throw new InvalidOperationException(Error.ClientNotFound);

                string clientId = await _applicationManager.GetIdAsync(application) ?? throw new NullReferenceException();

                CheckConsentClaim(result, parameters);

                var email = result.Principal!.FindFirst(ClaimTypes.Email)!.Value;

                var user = await _userManager.FindByEmailAsync(email);
                var claims = await _userManager.GetClaimsAsync(user);



                var roles = result.Principal.FindAll(ClaimTypes.Role)
                                            .Select(r => r.Value)
                                            .ToImmutableArray();

                IList<Claim> roleclaims = GetRoleClaims(result).Result;
                string subject = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

                ClaimsIdentity identity = SetIdentity(subject, email, roles, user.UserName, claims, roleclaims);
                identity.SetScopes(request.GetScopes());

                identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());


                var authorization = GetAuthorization(clientId, subject, identity).Result;

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(AuthService.GetDestination);

                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);


            }
            /*var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
                                                throw new InvalidOperationException(Error.ClientNotFound);



            var consentclaim = result.Principal!.GetClaim(Constant.ConsentNaming);

            if (consentclaim != Constant.GrantAccessValue)
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuilderRediect(HttpContext.Request, parameters));
                var consentRedirectUrl = Urls.ConsentWithReturnUrl + returnUrl;

                return Redirect(consentRedirectUrl);
            }*/

            /*var email = result.Principal!.FindFirst(ClaimTypes.Email)!.Value;

            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);



            var roles = result.Principal.FindAll(ClaimTypes.Role)
                                        .Select(r => r.Value)
                                        .ToImmutableArray();
            IList<Claim> roleclaims = new List<Claim>();*/

            /*foreach (var role in roles)
            {
                var roleObject = await _roleManager.FindByNameAsync(role);
                if (roleObject == null)
                {
                    continue; 
                }

                var rClaim = await _roleManager.GetClaimsAsync(roleObject);
                if (rClaim != null && rClaim.Any())
                {
                    foreach (var c in rClaim)
                    {
                        roleclaims.Add(c); 
                    }
                }
            }*/

            /*string _subject = result.Principal.FindFirst(ClaimTypes.Email)!.Value;
            var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, _subject)
                    .SetClaim(Claims.Email, email)
                    .SetClaims(Claims.Role, roles)
                    .SetClaim(Claims.PreferredUsername, user.UserName)
            ;*/

            /*foreach (var c in claims)
            {
                identity.SetClaim(c.Type, c.Value);
            }

            foreach (var c in roleclaims)
            {
                identity.SetClaim(c.Type, c.Value);
            }


            identity.SetScopes(request.GetScopes());

            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            */

            /*string _client = await _applicationManager.GetIdAsync(application) ?? throw new NullReferenceException();
            var authorizations = await _authorizationManager
               .FindAsync(
               subject: _subject,
               client: _client,
               status: Statuses.Valid,
               type: AuthorizationTypes.Permanent,
               scopes: identity.GetScopes()).ToListAsync();

            var authorization = authorizations.LastOrDefault();

            authorization ??= await _authorizationManager.CreateAsync(
                identity: identity,
                subject: _subject,
                client: _client,
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes());

            identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
            identity.SetDestinations(AuthService.GetDestination);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            */
        }

        private async Task<object> GetAuthorization(string clientId, string subject, ClaimsIdentity identity)
        {
            var authorizations = await _authorizationManager
                            .FindAsync(
                            subject: subject,
                            client: clientId,
                            status: Statuses.Valid,
                            type: AuthorizationTypes.Permanent,
                            scopes: identity.GetScopes()).ToListAsync();

            var authorization = authorizations.LastOrDefault();

            authorization ??= await _authorizationManager.CreateAsync(
                identity: identity,
                subject: subject,
                client: clientId,
                type: AuthorizationTypes.Permanent,
                scopes: identity.GetScopes());

            return authorization;
        }

        private ClaimsIdentity SetIdentity(string subject, string email,
                                            ImmutableArray<string> roles,
                                            string userName,
                                            IList<Claim> claims,
                                            IList<Claim> roleclaims)
        {
            var identity = new ClaimsIdentity(
                        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                        nameType: Claims.Name,
                        roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, subject)
                    .SetClaim(Claims.Email, email)
                    .SetClaims(Claims.Role, roles)
                    .SetClaim(Claims.PreferredUsername, userName)
            ;

            foreach (var c in claims)
            {
                identity.SetClaim(c.Type, c.Value);
            }

            foreach (var c in roleclaims)
            {
                identity.SetClaim(c.Type, c.Value);
            }

            return identity;
        }

        private async Task<List<Claim>> GetRoleClaims(AuthenticateResult result)
        {

            var roles = result.Principal!.FindAll(ClaimTypes.Role)
                                            .Select(r => r.Value)
                                            .ToImmutableArray();

            IList<Claim> roleclaims = new List<Claim>();

            foreach (var role in roles)
            {
                var roleObject = await _roleManager.FindByNameAsync(role);
                if (roleObject == null)
                {
                    continue;
                }

                var rClaim = await _roleManager.GetClaimsAsync(roleObject);
                if (rClaim != null && rClaim.Any())
                {
                    foreach (var c in rClaim)
                    {
                        roleclaims.Add(c);
                    }
                }
            }
            return roleclaims.ToList();
        }

        private RedirectResult CheckConsentClaim(AuthenticateResult result, IDictionary<string, StringValues> parameters)
        {

            if (result.Principal!.GetClaim(Constant.ConsentNaming) != Constant.GrantAccessValue)
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuilderRediect(HttpContext.Request, parameters));
                var consentRedirectUrl = Urls.ConsentWithReturnUrl + returnUrl;

                return Redirect(consentRedirectUrl);
            }
            return null!;
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

            var claims = result.Principal!;

            var email = claims.GetClaim(Claims.Email);
            var id = claims.GetClaim(Claims.ClientId);

            var role = claims.GetClaims(Claims.Role);
            var subject = claims.GetClaim(Claims.Email);
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

            var identity = new ClaimsIdentity(result.Principal.Claims,
                                                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                                                nameType: Claims.Name,
                                                roleType: Claims.Role);

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
