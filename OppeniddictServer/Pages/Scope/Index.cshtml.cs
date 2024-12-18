using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Scope
{
    public class IndexModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public IndexModel(OpenIddictDbContext context)
        {
            _context = context;
        }

        public IList<OpenIddictEntityFrameworkCoreScope> ScopesManager { get;set; } = default!;

        public async Task OnGetAsync()
        {
            if (_context.ScopesManager != null)
            {
                ScopesManager = await _context.ScopesManager.ToListAsync()??new();
            }
        }
    }
}
