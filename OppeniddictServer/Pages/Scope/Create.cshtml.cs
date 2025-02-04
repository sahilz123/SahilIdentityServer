using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Pages.Scope
{
    public class CreateModel : PageModel
    {
        //private readonly OpenIddictDbContext _context;
        private readonly ScopesManager  _scopemanager;
        private readonly AuthService _authService;


        public CreateModel(ScopesManager scopemanager , AuthService authService)
        {
            //_context = context;
            _scopemanager = scopemanager;
            _authService = authService;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public ScopeInputModel ScopesManager { get; set; } = default!;
        public string Status=default!;


        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || ScopesManager == null)
            {
                return Page();
            }

            ScopesManager.Resources = _authService.PopulateStringToList(ScopesManager.Resources![0]);
            Status = await _scopemanager.CreateAsync(ScopesManager) ;
            //Status = await _seeder.AddScopes(ScopesManager) ;
   
            return RedirectToPage(Urls.Index);
        }

        public class ScopeInputModel
        {
            public string Name { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
            public string? Description { get; set; }
            public string? Properties { get; set; }
            public List<string>? Resources { get; set; }

            
        }

    }
}
