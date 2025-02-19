using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Constants;
using OppeniddictServer.Model;
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

       
        [BindProperty]
        public ApplicationRegisterData Client { get; set; } = new()!;

        [BindProperty]
        public IList<OpenIddictEntityFrameworkCoreScope> AvailableScopes { get; set; } = default!;

        //[BindProperty]
        //[Required]
        //public List<string> SelectedScopes { get; set; } = new List<string>();

        //[BindProperty]
        //public List<string> SelectedPermission { get; set; } = new List<string>();

        [BindProperty]
        public List<SelectListItem> Permission { get; set; }= new();
        
        [BindProperty]
        public List<SelectListItem> ClientType { get; set; }= new();
        
        [BindProperty]
        public List<SelectListItem> ConsentType { get; set; }= new();

        public async Task<IActionResult> OnGet()
        {
            AvailableScopes = await _scope.GetAvailableScopes();
            ClientType=ApplicationDropdownData.GetClientType();
            Permission = ApplicationDropdownData.GetPermissions();
            ConsentType=ApplicationDropdownData.GetConsentType();
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid || Client == null)
            {
                return Page();
            }
            //Client.Scopes = SelectedScopes;
            Client.RedirectUris = _authService.PopulateStringToList(Client.RedirectUris![0]);
            //Client.Permissions= _authService.PopulateStringToList(Client.Permissions![0]);
            //Client.Permissions = SelectedPermission;
            Client.PostLogoutRedirectUris = _authService.PopulateStringToList(Client.PostLogoutRedirectUris![0]);
            await _seeder.AddClients(Client);

            return RedirectToPage(Urls.Index);
        }

    }    

}
