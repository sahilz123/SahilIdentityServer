using Humanizer.Localisation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Constants;
using OppeniddictServer.Openiddict;
using System.ComponentModel.DataAnnotations;

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

            return Page();
        }

        [BindProperty]
        public RegisterInput Client { get; set; } = default!;
        
        [BindProperty]
        public IList<OpenIddictEntityFrameworkCoreScope> AvailableScopes { get; set; } = default!;

        [BindProperty]
        [Required]
        public List<string> SelectedScopes { get; set; } = new List<string>();

        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid ||  Client == null)
            {
                return Page();
            }
            Client.Scopes = SelectedScopes;
            Client.RedirectUris= _authService.PopulateStringToList(Client.RedirectUris![0],Client.RedirectUris);
            Client.Permissions= _authService.PopulateStringToList(Client.Permissions![0],Client.Permissions);
            Client.PostLogoutRedirectUris= _authService.PopulateStringToList(Client.PostLogoutRedirectUris![0], Client.PostLogoutRedirectUris);
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
