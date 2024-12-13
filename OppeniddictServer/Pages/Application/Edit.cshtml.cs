using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Application
{
    [Authorize(Roles = "Admin")]
    public class EditModel : PageModel
    {
        private readonly OppeniddictServer.Context.OpenIddictDbContext _context;

        public EditModel(OppeniddictServer.Context.OpenIddictDbContext context)
        {
            _context = context;
        }

        [BindProperty]
        public OpenIddictEntityFrameworkCoreApplication ApplicationManager { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.ApplicationManager == null)
            {
                return NotFound();
            }

            var applicationmanager =  await _context.ApplicationManager.FirstOrDefaultAsync(m => m.Id == id);
            if (applicationmanager == null)
            {
                return NotFound();
            }
            ApplicationManager = applicationmanager;
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

            _context.Attach(ApplicationManager).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!ApplicationManagerExists(ApplicationManager.Id))
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

        private bool ApplicationManagerExists(string id)
        {
          return (_context.ApplicationManager?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
