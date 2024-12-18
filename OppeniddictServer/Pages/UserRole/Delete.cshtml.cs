using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.UserRole
{
    public class DeleteModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public DeleteModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        [BindProperty]
      public UserIdentityUserRole UserIdentityUserRole { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.UserRoles == null)
            {
                return NotFound();
            }

            var useridentityuserrole = await _context.UserRoles.FirstOrDefaultAsync(m => m.UserId == id);

            if (useridentityuserrole == null)
            {
                return NotFound();
            }
            else 
            {
                UserIdentityUserRole = useridentityuserrole;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string id)
        {
            if (id == null || _context.UserRoles == null)
            {
                return NotFound();
            }
            var useridentityuserrole = await _context.UserRoles.FindAsync(id);

            if (useridentityuserrole != null)
            {
                UserIdentityUserRole = useridentityuserrole;
                _context.UserRoles.Remove(UserIdentityUserRole);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage("./Index");
        }
    }
}
