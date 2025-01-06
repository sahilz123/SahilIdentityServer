using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;
using OppeniddictServers.Identity;

namespace OppeniddictServer.Pages.UserClaim
{
    public class IndexModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;
        private readonly UserManager<UserIdentity> _userManager;

        public IndexModel(AdminIdentityDbContext context, UserManager<UserIdentity> userManager)
        {
            _context = context;
            _userManager = userManager;
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
