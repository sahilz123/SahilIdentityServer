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

namespace OppeniddictServer.Pages.UserClaim
{
    public class DeleteModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;

        public DeleteModel(AdminIdentityDbContext context)
        {
            _context = context;
        }

        [BindProperty]
      public UserIdentityUserClaim UserIdentityUserClaim { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(int? id)
        {
            if (id == null || _context.UserClaims == null)
            {
                return NotFound();
            }

            var useridentityuserclaim = await _context.UserClaims.FirstOrDefaultAsync(m => m.Id == id);

            if (useridentityuserclaim == null)
            {
                return NotFound();
            }
            else 
            {
                UserIdentityUserClaim = useridentityuserclaim;
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(int? id)
        {
            if (id == null || _context.UserClaims == null)
            {
                return NotFound();
            }
            var useridentityuserclaim = await _context.UserClaims.FindAsync(id);

            if (useridentityuserclaim != null)
            {
                UserIdentityUserClaim = useridentityuserclaim;
                _context.UserClaims.Remove(UserIdentityUserClaim);
                await _context.SaveChangesAsync();
            }

            return RedirectToPage(Urls.Index);
        }
    }
}
