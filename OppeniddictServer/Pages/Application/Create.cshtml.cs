using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Context;
using OppeniddictServer.Model;
using OppeniddictServer.Openiddict;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OppeniddictServer.Pages.Application
{
    [Authorize(Roles ="Admin")]
    public class CreateModel : PageModel
    {
        private readonly OpenIddictDbContext _context;
        private readonly ClientSeeder _seeder;
        private readonly ScopesManager _scope;

        public CreateModel(OpenIddictDbContext context,ClientSeeder seeder, ScopesManager scope)
        {
            _context = context;
            _seeder = seeder;
            _scope = scope;
        }

        public async Task<IActionResult> OnGet()
        {
            AvailableScopes =  await _scope.GetAvailableScopes();

            return Page();
        }

        [BindProperty]
        public ApplicationManager ApplicationManager { get; set; } = default!;
        
        [BindProperty]
        public IList<OpenIddictEntityFrameworkCoreScope> AvailableScopes { get; set; } = default!;

        [BindProperty]
        public List<string> SelectedScopes { get; set; } = new List<string>();


        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.ApplicationManager == null || ApplicationManager == null)
            {
                return Page();
            }

            var registerInput = new RegisterInput()
            {
                ClientId = ApplicationManager.ClientId,
                DisplayName = ApplicationManager.DisplayName,
                RedirectUris = ApplicationManager.RedirectUris,
                Permissions = ApplicationManager.Permissions,
                Scopes = SelectedScopes
            };
            var seedclient= _seeder.AddClients(registerInput).GetAwaiter().GetResult();

            return RedirectToPage("./Index");
        }
    }

    
}
