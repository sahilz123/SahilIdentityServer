using OpenIddict.Abstractions;
using OppeniddictServer.Context;
using OppeniddictServer.Model;
using Polly;
using System;
using System.Collections.Generic;
using System.Net;
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

        public async Task<string> AddClients(RegisterInput newClient)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();            
            var context = scope.ServiceProvider.GetRequiredService<OpenIddictDbContext>();

            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();


            var client = await manager.FindByClientIdAsync(newClient.ClientId.ToString()!);

            if (client != null)
            {
                return "Client Already Exist";
                //await manager.DeleteAsync(client);
            }
            else
            {                
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    
                    ClientSecret = Guid.NewGuid().ToString(),
                    ClientId = newClient.ClientId.ToString(),
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = newClient.DisplayName,
                    RedirectUris = 
                    {
                       new Uri(newClient.RedirectUris!.Trim())
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
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
                });

                return $"Client Created {newClient.ClientId}";
            }
        }

        public async Task<object?> CheckClient(string clientid="user")
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<OpenIddictDbContext>();

            await context.Database.EnsureCreatedAsync(); 
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            return await manager.FindByClientIdAsync(clientid);
        }

    }
}
