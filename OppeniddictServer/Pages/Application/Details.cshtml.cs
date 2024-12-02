using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Application
{
    public class DetailsModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public DetailsModel(OpenIddictDbContext context)
        {
            _context = context;
        }

      public ApplicationManager ApplicationManager { get; set; } = default!; 

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
    }
}
