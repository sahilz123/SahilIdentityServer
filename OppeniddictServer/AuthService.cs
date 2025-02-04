using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OppeniddictServer
{
    public class AuthService
    {
        public static List<string> GetDestination(Claim claim)
        {
            var destination = new List<string>();
            if (claim.Type == Claims.Name || claim.Type == Claims.Email || claim.Type == Claims.Role )                                                          //||claim.Type== "ADMIN_Write")
            {
                destination.Add(Destinations.AccessToken);
            }
            return destination;           
        }
        public string BuilderRediect(HttpRequest request,IDictionary<string,StringValues> parameters)
        {
                       
            var url = request.PathBase + request.Path + QueryString.Create(parameters);
            return url;
        }
        public IDictionary<string,StringValues> ParseOAuthParameters(HttpContext httpContext,List<string?> excluding =null!)
        {
            excluding ??= new List<string>()!;
            var parameters = httpContext.Request.HasFormContentType ?

                httpContext.Request.Form.Where(parameter => !excluding.Contains(parameter.Key))
                .ToDictionary(K => K.Key, k => k.Value) :

                httpContext.Request.Query.Where(parameter => !excluding.Contains(parameter.Key))

                .ToDictionary(K => K.Key, k => k.Value);

            return parameters;
        }
        public bool IsAuthenticated(AuthenticateResult authenticateResult,OpenIddictRequest request)
        {
            if (!authenticateResult.Succeeded)
            {
                return false;
            }

            if (request.MaxAge.HasValue && authenticateResult.Properties != null)
            {
                var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);
                var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                    DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeSeconds;

                if (expired) { return false; }
            }
                return true;
            
        }

        public List<string> PopulateStringToList(string res)
        {
            List<string> ResourcesList = new();
            if (!string.IsNullOrEmpty(res))
            {
                ResourcesList.Clear();
                ResourcesList = res
                    .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(item => item.Trim())
                    .ToList();
                ResourcesList.RemoveAll(x => x == "");
                ResourcesList = ResourcesList.Distinct().ToList();

            }
            else
            {
                ResourcesList.Clear();
            }

            return ResourcesList;
        }
    }
}
