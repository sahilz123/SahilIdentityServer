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
    public class IndexModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public IndexModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        public IList<UserIdentityRole> UserIdentityRole { get;set; } = default!;

        public async Task OnGetAsync()
        {
            if (_context.Roles != null)
            {
                UserIdentityRole = await _context.Roles.ToListAsync();
            }
        }
    }
}
