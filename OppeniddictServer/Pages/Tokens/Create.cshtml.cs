using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Tokens
{
    public class CreateModel : PageModel
    {
        private readonly OppeniddictServer.Context.OpenIddictDbContext _context;

        public CreateModel(OppeniddictServer.Context.OpenIddictDbContext context)
        {
            _context = context;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public TokenManager TokenManager { get; set; } = default!;
        

        // To protect from overposting attacks, see https://aka.ms/RazorPagesCRUD
        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.TokenManager == null || TokenManager == null)
            {
                return Page();
            }

            _context.TokenManager.Add(TokenManager);
            await _context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
    }
}
