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

namespace OppeniddictServer.Pages.Tokens
{
    public class DetailsModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public DetailsModel(OpenIddictDbContext context)
        {
            _context = context;
        }

      public OpenIddictEntityFrameworkCoreToken TokenManager { get; set; } = default!; 

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.TokenManager == null)
            {
                return NotFound();
            }

            var tokenmanager = await _context.TokenManager.FirstOrDefaultAsync(m => m.Id == id);
            if (tokenmanager == null)
            {
                return NotFound();
            }
            else 
            {
                TokenManager = tokenmanager;
            }
            return Page();
        }
    }
}
