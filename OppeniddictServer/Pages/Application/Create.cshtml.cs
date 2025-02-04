using Humanizer.Localisation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Constants;
using OppeniddictServer.Openiddict;
using System.ComponentModel.DataAnnotations;
using System.Security;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OppeniddictServer.Pages.Application
{
    public class CreateModel : PageModel
    {
        private readonly ClientSeeder _seeder;
        private readonly ScopesManager _scope;
        private readonly AuthService _authService;

        public CreateModel(ClientSeeder seeder, ScopesManager scope, AuthService authService)
        {
            _seeder = seeder;
            _scope = scope;
            _authService = authService;
        }

        public async Task<IActionResult> OnGet()
        {
            AvailableScopes =  await _scope.GetAvailableScopes();

            var g1 = new SelectListGroup() { Name = "Endpoints" };
            var g2 = new SelectListGroup() { Name = "GrantTypes"};
            var g3 = new SelectListGroup() { Name = "Permission-Scopes" };
            var g4 = new SelectListGroup() { Name = "ResponseType" };
            var g5 = new SelectListGroup() { Name = "Scope" };

            // Language List
            Permission = new List<SelectListItem>
        {
            new () { Text = "Authorization", Value = Permissions.Endpoints.Authorization, Group = g1 },
            new () { Text = "Device", Value = Permissions.Endpoints.Device, Group = g1 },
            new () { Text = "Revocation", Value = Permissions.Endpoints.Revocation, Group = g1 },
            new () { Text = "Token", Value = Permissions.Endpoints.Token, Group = g1 },
            new () { Text = "Logout", Value = Permissions.Endpoints.Logout, Group = g1 },

            new () { Text = "AuthorizationCode", Value = Permissions.GrantTypes.AuthorizationCode, Group = g2 },
            new () { Text = "ClientCredentials", Value = Permissions.GrantTypes.RefreshToken, Group = g2 },
            new () { Text = "DeviceCode", Value = Permissions.GrantTypes.RefreshToken, Group = g2 },
            new () { Text = "Implicit", Value = Permissions.GrantTypes.RefreshToken, Group = g2 },

            new () { Text = "Email", Value = Permissions.Scopes.Email, Group = g3 },
            new () { Text = "Roles", Value = Permissions.Scopes.Roles, Group = g3 },
            new () { Text = "Address", Value = Permissions.Scopes.Address, Group = g3 },
            new () { Text = "Profile", Value = Permissions.Scopes.Profile, Group = g3 },
            new () { Text = "Phone", Value = Permissions.Scopes.Phone, Group = g3 },

            new () { Text = "Code", Value = Permissions.ResponseTypes.Code, Group = g4 },
            new () { Text = "CodeToken", Value = Permissions.ResponseTypes.CodeToken, Group = g4 },
            new () { Text = "CodeIdToken", Value = Permissions.ResponseTypes.CodeIdToken, Group = g4 },
            new () { Text = "Token", Value = Permissions.ResponseTypes.Token, Group = g4 },

            new () { Text = "OpenId", Value = Scopes.OpenId, Group = g5 },
            new () { Text = "OfflineAccess", Value = Scopes.OfflineAccess, Group = g5 },

            
        };
            return Page();
        }

        [BindProperty]
        public RegisterInput Client { get; set; } = default!;
        
        [BindProperty]
        public IList<OpenIddictEntityFrameworkCoreScope> AvailableScopes { get; set; } = default!;

        [BindProperty]
        [Required]
        public List<string> SelectedScopes { get; set; } = new List<string>();
        
        [BindProperty]
        public List<string> SelectedPermission { get; set; } = new List<string>();
        
        [BindProperty]
        public List<SelectListItem> Permission { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid ||  Client == null)
            {
                return Page();
            }                   
            Client.Scopes = SelectedScopes;
            Client.RedirectUris= _authService.PopulateStringToList(Client.RedirectUris![0]);
            //Client.Permissions= _authService.PopulateStringToList(Client.Permissions![0]);
            Client.Permissions= SelectedPermission;
            Client.PostLogoutRedirectUris= _authService.PopulateStringToList(Client.PostLogoutRedirectUris![0]);
            await _seeder.AddClients(Client);

            return RedirectToPage(Urls.Index);
        }
    }
    public class RegisterInput
    {
        public string? ClientId { get; set; }
        public string? ClientType { get; set; }
        public string? ConsentType { get; set; }
        public string? DisplayName { get; set; }
        public string? Properties { get; set; }
        public List<string>? RedirectUris { get; set; } 
        public List<string>? Permissions { get; set; } 
        public List<string>? Scopes { get; set; } 
        public List<string>? PostLogoutRedirectUris { get; set; } 

       
    }


}
