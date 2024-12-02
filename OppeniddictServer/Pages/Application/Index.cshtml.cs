using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Openiddict;
using OppeniddictServer.Context;

namespace OppeniddictServer.Pages.Application
{
    public class IndexModel : PageModel
    {
        private readonly OpenIddictDbContext _context;

        public IndexModel(OpenIddictDbContext context)
        {
            _context = context;
        }

        public IList<ApplicationManager> ApplicationManager { get;set; } = default!;

        public async Task OnGetAsync()
        {
            
            if (_context.ApplicationManager != null)
            {
                ApplicationManager = await _context.ApplicationManager.ToListAsync();
            }
        }
    }
}
