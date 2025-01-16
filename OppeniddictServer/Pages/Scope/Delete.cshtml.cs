using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Scope
{
    public class DeleteModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public DeleteModel(OpenIddictDbContext context)
        {
            _context = context;
        }

        [BindProperty]
      public OpenIddictEntityFrameworkCoreScope ScopesManager { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.ScopesManager == null)
            {
                return NotFound();
            }

            var scopesmanager = await _context.ScopesManager.FirstOrDefaultAsync(m => m.Id == id);

            if (scopesmanager == null)
            {
                return NotFound();
            }
            else 
            {
                ScopesManager = scopesmanager;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string id)
        {
            if (id == null || _context.ScopesManager == null)
            {
                return NotFound();
            }
            var scopesmanager = await _context.ScopesManager.FindAsync(id);

            if (scopesmanager != null)
            {
                ScopesManager = scopesmanager;
                _context.ScopesManager.Remove(ScopesManager);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage(Urls.Index);
        }
    }
}
