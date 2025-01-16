using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.RoleClaim
{
    public class EditModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;

        public EditModel(AdminIdentityDbContext context)
        {
            _context = context;
        }

        [BindProperty]
        public UserIdentityRoleClaim UserIdentityRoleClaim { get; set; } = default!;

        public async Task<IActionResult> OnGetAsync(string? id)
        {
            if (id == null || _context.RoleClaims == null)
            {
                return NotFound();
            }

            var useridentityroleclaim =  await _context.RoleClaims.FirstOrDefaultAsync(m => m.RoleId == id);
            if (useridentityroleclaim == null)
            {
                return NotFound();
            }
            UserIdentityRoleClaim = useridentityroleclaim;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            _context.Attach(UserIdentityRoleClaim).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserIdentityRoleClaimExists(UserIdentityRoleClaim.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return RedirectToPage(Urls.Index);
        }

        private bool UserIdentityRoleClaimExists(int id)
        {
          return (_context.RoleClaims?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
