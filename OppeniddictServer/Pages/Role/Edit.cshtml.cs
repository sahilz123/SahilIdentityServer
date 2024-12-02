using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.Role
{
    public class EditModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public EditModel(OppeniddictServer.Context.AdminIdentityDbContext context)
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

            var useridentityrole =  await _context.Roles.FirstOrDefaultAsync(m => m.Id == id);
            if (useridentityrole == null)
            {
                return NotFound();
            }
            UserIdentityRole = useridentityrole;
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

            _context.Attach(UserIdentityRole).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserIdentityRoleExists(UserIdentityRole.Id))
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

        private bool UserIdentityRoleExists(string id)
        {
          return (_context.Roles?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
