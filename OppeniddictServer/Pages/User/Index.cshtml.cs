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
    public class IndexModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;

        public IndexModel(AdminIdentityDbContext context)
        {
            _context = context;
        }

        public IList<UserIdentity> UserIdentity { get;set; } = default!;

        public async Task OnGetAsync()
        {
            if (_context.Users != null)
            {
                UserIdentity = await _context.Users.ToListAsync();
            }
        }
    }
}
