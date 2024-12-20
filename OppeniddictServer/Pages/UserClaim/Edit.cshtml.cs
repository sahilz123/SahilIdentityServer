using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServers.Identity;

namespace OppeniddictServer.Pages.UserClaim
{
    public class EditModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public EditModel(OppeniddictServer.Context.AdminIdentityDbContext context)
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

            var useridentityuserclaim =  await _context.UserClaims.FirstOrDefaultAsync(m => m.Id == id);
            if (useridentityuserclaim == null)
            {
                return NotFound();
            }
            UserIdentityUserClaim = useridentityuserclaim;
            return Page();
        }

        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see https://aka.ms/RazorPagesCRUD.
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            _context.Attach(UserIdentityUserClaim).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserIdentityUserClaimExists(UserIdentityUserClaim.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return RedirectToPage("./Index");
        }

        private bool UserIdentityUserClaimExists(int id)
        {
          return (_context.UserClaims?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
