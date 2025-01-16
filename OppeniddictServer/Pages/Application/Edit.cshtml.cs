using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;

namespace OppeniddictServer.Pages.Application
{
    [Authorize(Roles = Roles.SuperAdmin)]
    public class EditModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public EditModel(OpenIddictDbContext context)
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
                if (!ApplicationManagerExists(ApplicationManager.Id!))
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

        private bool ApplicationManagerExists(string id)
        {
          return (_context.ApplicationManager?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
