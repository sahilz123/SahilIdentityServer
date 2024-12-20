using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServers.Identity;

namespace OppeniddictServer.Pages.UserClaim
{
    public class IndexModel : PageModel
    {
        private readonly OppeniddictServer.Context.AdminIdentityDbContext _context;

        public IndexModel(OppeniddictServer.Context.AdminIdentityDbContext context)
        {
            _context = context;
        }

        public IList<UserIdentityUserClaim> UserIdentityUserClaim { get;set; } = default!;

        public async Task OnGetAsync()
        {
            if (_context.UserClaims != null)
            {
                UserIdentityUserClaim = await _context.UserClaims.ToListAsync();
            }
        }
    }
}
