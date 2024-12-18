using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.RoleClaim
{
    public class CreateModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public CreateModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public UserIdentityRoleClaim UserIdentityRoleClaim { get; set; } = default!;
        

        // To protect from overposting attacks, see https://aka.ms/RazorPagesCRUD
        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.RoleClaims == null || UserIdentityRoleClaim == null)
            {
                return Page();
            }

            _context.RoleClaims.Add(UserIdentityRoleClaim);
            await _context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
    }
}
