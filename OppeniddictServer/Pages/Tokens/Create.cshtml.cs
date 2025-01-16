using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Tokens
{
    public class CreateModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public CreateModel(OpenIddictDbContext context)
        {
            _context = context;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public TokenManager TokenManager { get; set; } = default!;
        

        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.TokenManager == null || TokenManager == null)
            {
                return Page();
            }

            _context.TokenManager.Add(TokenManager);
            await _context.SaveChangesAsync();

            return RedirectToPage(Urls.Index);
        }
    }
}
