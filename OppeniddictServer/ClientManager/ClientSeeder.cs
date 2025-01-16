using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Pages.Application;
using System.Text;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OppeniddictServer.Pages.Scope.CreateModel;

namespace OppeniddictServer.ClientManager
{
    public class ClientSeeder
    {
        private readonly IServiceProvider _serviceProvider;
        public ClientSeeder(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task<string> AddScopes(ScopeInputModel scopeInput = null!)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
           // var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
            var manager = scope.ServiceProvider.GetRequiredService<OpenIddictScopeManager<OpenIddictEntityFrameworkCoreScope>>();

            var apiscope = await manager.FindByNameAsync(scopeInput.Name);

            if (apiscope != null)
            {
                await manager.DeleteAsync(apiscope);
            }

            var scopeDescriptor = new OpenIddictScopeDescriptor
            {
                Description = scopeInput.Description,
                DisplayName = scopeInput.DisplayName,
                Name = scopeInput.Name,
            };

            if (scopeInput.ResourcesList?.Count > 0)
            {
                foreach (var resource in scopeInput.ResourcesList)
                {
                    scopeDescriptor.Resources.Add(resource);
                }
            }

            await manager.CreateAsync(scopeDescriptor);

            return $"Scope Created {scopeInput.Name}";
           
        }

        public async Task<string> AddClients(RegisterInput newClient)
        {
            StringBuilder scopestring =new("");

            foreach(var x in newClient.Scopes!)
            {
                scopestring.Append(x+" ");
            }
            await using var scope = _serviceProvider.CreateAsyncScope();            
            var context = scope.ServiceProvider.GetRequiredService<OpenIddictDbContext>();

            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();


            var client = await manager.FindByClientIdAsync(newClient.ClientId!.ToString()!);

            if (client != null)
            {
                return Constant.ClientAlreadyExist;
                //await manager.DeleteAsync(client);
            }
            else
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {

                    ClientSecret = Guid.NewGuid().ToString(),
                    ClientId = newClient.ClientId.ToString(),
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = newClient.DisplayName,
                   
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


                        $"{Permissions.Prefixes.Scope}{scopestring}"
                    },
                    Requirements =
                    {
                        //Requirements.Features.ProofKeyForCodeExchange
                    }
                };

                foreach (var uri in newClient.RedirectUris!.Where(uri => !string.IsNullOrWhiteSpace(uri)))
                {
                    descriptor.RedirectUris.Add(new Uri(uri.Trim()));
                }


                await manager.CreateAsync(descriptor);

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
