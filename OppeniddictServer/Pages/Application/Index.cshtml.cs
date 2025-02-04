using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Openiddict;
using OppeniddictServer.Context;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.EntityFrameworkCore.Models;
using Microsoft.AspNetCore.Authorization;
using OppeniddictServer.Constants;
using NuGet.Protocol;
using OpenIddict.Abstractions;

namespace OppeniddictServer.Pages.Application
{
    [Authorize(Roles = Roles.SuperAdmin)]
    public class IndexModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public IndexModel(OpenIddictDbContext context)
        {
            _context = context;
        }
        public IList<OpenIddictEntityFrameworkCoreApplication> ApplicationManager { get;set; } = default!;

        public async Task OnGetAsync()
        {
            if (_context.ApplicationManager != null)
            {
                ApplicationManager = await _context.ApplicationManager.ToListAsync();
            }
        }
    }
}
