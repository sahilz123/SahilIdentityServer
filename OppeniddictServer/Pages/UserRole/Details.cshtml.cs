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
    public class DetailsModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;

        public DetailsModel(AdminIdentityDbContext context)
        {
            _context = context;
        }

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
    }
}
