using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Tokens
{
    public class EditModel : PageModel
    {
        private readonly OppeniddictServer.Context.OpenIddictDbContext _context;

        public EditModel(OppeniddictServer.Context.OpenIddictDbContext context)
        {
            _context = context;
        }

        [BindProperty]
        public OpenIddictEntityFrameworkCoreToken TokenManager { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.TokenManager == null)
            {
                return NotFound();
            }

            var tokenmanager =  await _context.TokenManager.FirstOrDefaultAsync(m => m.Id == id);
            if (tokenmanager == null)
            {
                return NotFound();
            }
            TokenManager = tokenmanager;
            return Page();
        }

        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see https://aka.ms/RazorPagesCRUD.
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            _context.Attach(TokenManager).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TokenManagerExists(TokenManager.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return RedirectToPage("./Index");
        }

        private bool TokenManagerExists(string id)
        {
          return (_context.TokenManager?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
