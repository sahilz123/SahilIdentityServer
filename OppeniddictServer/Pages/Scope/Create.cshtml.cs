using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Scope
{
    public class CreateModel : PageModel
    {
        private readonly OpenIddictDbContext _context;
        //private readonly ClientSeeder scopes;
        private readonly ScopesManager scopes;

        public CreateModel(OpenIddictDbContext context, ScopesManager scopes)
        {
            _context = context;
            this.scopes = scopes;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public ScopeInputModel ScopesManager { get; set; } = default!;
        public string Status;


        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.ScopesManager == null || ScopesManager == null)
            {
                return Page();
            }

            Status = await scopes.CreateAsync(ScopesManager);
   
            return RedirectToPage("./Index");
        }

        public class ScopeInputModel
        {
            public string Name { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
            public string? Description { get; set; }
            public string? Properties { get; set; }
            public List<string> Resources { get; set; } = new List<string>();
        }

    }
}
