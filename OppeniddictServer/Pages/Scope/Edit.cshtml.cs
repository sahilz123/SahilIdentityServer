using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Scope
{
    public class EditModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public EditModel(OpenIddictDbContext context)
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

            var scopesmanager =  await _context.ScopesManager.FirstOrDefaultAsync(m => m.Id == id);
            if (scopesmanager == null)
            {
                return NotFound();
            }
            ScopesManager = scopesmanager;
            return Page();
        }
 
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            _context.Attach(ScopesManager).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ScopesManagerExists(ScopesManager.Id!))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return RedirectToPage(Urls.Index);
        }

        private bool ScopesManagerExists(string id)
        {
          return (_context.ScopesManager?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
