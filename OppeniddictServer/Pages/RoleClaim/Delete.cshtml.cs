using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.RoleClaim
{
    public class DeleteModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public DeleteModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        [BindProperty]
      public UserIdentityRoleClaim UserIdentityRoleClaim { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(int? id)
        {
            if (id == null || _context.RoleClaims == null)
            {
                return NotFound();
            }

            var useridentityroleclaim = await _context.RoleClaims.FirstOrDefaultAsync(m => m.Id == id);

            if (useridentityroleclaim == null)
            {
                return NotFound();
            }
            else 
            {
                UserIdentityRoleClaim = useridentityroleclaim;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(int? id)
        {
            if (id == null || _context.RoleClaims == null)
            {
                return NotFound();
            }
            var useridentityroleclaim = await _context.RoleClaims.FindAsync(id);

            if (useridentityroleclaim != null)
            {
                UserIdentityRoleClaim = useridentityroleclaim;
                _context.RoleClaims.Remove(UserIdentityRoleClaim);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage(Urls.Index);
        }
    }
}
