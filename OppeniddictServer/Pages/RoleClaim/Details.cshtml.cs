using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.RoleClaim
{
    public class DetailsModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;

        public DetailsModel(AdminIdentityDbContext context)
        {
            _context = context;
        }

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
    }
}
