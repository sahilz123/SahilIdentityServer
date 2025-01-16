using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Scope
{
    public class DetailsModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public DetailsModel(OpenIddictDbContext context)
        {
            _context = context;
        }

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
    }
}
