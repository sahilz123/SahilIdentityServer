using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.User
{
    public class DeleteModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public DeleteModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        [BindProperty]
      public UserIdentity UserIdentity { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.Users == null)
            {
                return NotFound();
            }

            var useridentity = await _context.Users.FirstOrDefaultAsync(m => m.Id == id);

            if (useridentity == null)
            {
                return NotFound();
            }
            else 
            {
                UserIdentity = useridentity;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string id)
        {
            if (id == null || _context.Users == null)
            {
                return NotFound();
            }
            var useridentity = await _context.Users.FindAsync(id);

            if (useridentity != null)
            {
                UserIdentity = useridentity;
                _context.Users.Remove(UserIdentity);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage("./Index");
        }
    }
}
