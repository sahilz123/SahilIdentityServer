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

namespace OppeniddictServer.Pages.Application
{
    public class DeleteModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public DeleteModel(OpenIddictDbContext context)
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

            var applicationmanager = await _context.ApplicationManager.FirstOrDefaultAsync(m => m.Id == id);

            if (applicationmanager == null)
            {
                return NotFound();
            }
            else 
            {
                ApplicationManager = applicationmanager;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string id)
        {
            if (id == null || _context.ApplicationManager == null)
            {
                return NotFound();
            }
            var applicationmanager = await _context.ApplicationManager.FindAsync(id);

            if (applicationmanager != null)
            {
                ApplicationManager = applicationmanager;
                _context.ApplicationManager.Remove(ApplicationManager);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage(Urls.Index);
        }
    }
}
