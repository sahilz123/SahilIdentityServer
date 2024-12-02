using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.Role
{
    public class DeleteModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public DeleteModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        [BindProperty]
      public UserIdentityRole UserIdentityRole { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.Roles == null)
            {
                return NotFound();
            }

            var useridentityrole = await _context.Roles.FirstOrDefaultAsync(m => m.Id == id);

            if (useridentityrole == null)
            {
                return NotFound();
            }
            else 
            {
                UserIdentityRole = useridentityrole;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string id)
        {
            if (id == null || _context.Roles == null)
            {
                return NotFound();
            }
            var useridentityrole = await _context.Roles.FindAsync(id);

            if (useridentityrole != null)
            {
                UserIdentityRole = useridentityrole;
                _context.Roles.Remove(UserIdentityRole);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage("./Index");
        }
    }
}
