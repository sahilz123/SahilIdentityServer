using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OppeniddictServer.ClientManager
{
    public class ClientSeeder
    {
        private readonly IServiceProvider _serviceProvider;
        public ClientSeeder(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task AddScopes()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            var apiscope = await manager.FindByNameAsync("api1");

            if (apiscope != null)
            {
                await manager.DeleteAsync(apiscope);
            }

            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                DisplayName = "API Scope",                      //can be saved in database for client
                Name = "api1",
                Resources ={
                    "resource_server_1"
                    }
            });
        }

        public async Task AddClients()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var client = await manager.FindByClientIdAsync("web-client");

            if (client != null)
            {
                await manager.DeleteAsync(client);
            }
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-client",
                
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "WEB application",               
                RedirectUris =
                {
                       // new Uri("https://localhost:44310/Account/Register"),
                    new Uri("https://localhost:7002/swagger/oauth2-redirect.html"),

                    new Uri("https://localhost:7205"),
                    new Uri("https://localhost:7205/swagger/oauth2-redirect.html"),
                    new Uri("http://localhost:3000/login"),
                    new Uri("http://localhost:3000/Dashboard")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:7002/resources"),
                    new Uri("https://localhost:7205/resources"),
                    new Uri("https://localhost:3000/resources")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,

                    Permissions.GrantTypes.RefreshToken,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.GrantTypes.AuthorizationCode,

                    Permissions.ResponseTypes.Code,

                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Scopes.OfflineAccess,
                    Scopes.OpenId,
                    $"{Permissions.Prefixes.Scope}api1"
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }
    }
}
