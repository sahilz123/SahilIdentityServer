using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OppeniddictServer.Context;
using OppeniddictServer.Model;
using OppeniddictServer.Openiddict;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OppeniddictServer.Pages.Application
{
    public class CreateModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public CreateModel(OpenIddictDbContext context)
        {
            _context = context;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public ApplicationManager ApplicationManager { get; set; } = default!;
        

        // To protect from overposting attacks, see https://aka.ms/RazorPagesCRUD
        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.ApplicationManager == null || ApplicationManager == null)
            {
                return Page();
            }

            _context.ApplicationManager.Add(ApplicationManager);
            await _context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }

/*        public async Task<string> AddClients(RegisterInput newClient)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            //var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            //await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            //var client = await manager.FindByClientIdAsync("web-client");
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
                    //Requirements =
                    //{
                    //    Requirements.Features.ProofKeyForCodeExchange
                    //}
                });

                return $"Client Created {newClient.ClientId}";
            }
        }
*/
    }
}
