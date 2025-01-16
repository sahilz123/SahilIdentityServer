using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;

namespace OppeniddictServer.Pages.Scope
{
    public class CreateModel : PageModel
    {
        private readonly OpenIddictDbContext _context;
        private readonly ClientSeeder _seeder;

        public CreateModel(OpenIddictDbContext context,  ClientSeeder seeder)
        {
            _context = context;
            _seeder = seeder;
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
          if (!ModelState.IsValid || _context.ScopesManager == null || ScopesManager == null)
            {
                return Page();
            }
            ScopesManager.PopulateResourcesList();

            Status = await _seeder.AddScopes(ScopesManager) ;
   
            return RedirectToPage(Urls.Index);
        }

        public class ScopeInputModel
        {
            public string Name { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
            public string? Description { get; set; }
            public string? Properties { get; set; }
            public string? Resources { get; set; }

            public List<string> ResourcesList { get; set; } = new List<string>();

            public void PopulateResourcesList()
            {
                if (!string.IsNullOrEmpty(Resources))
                {
                    ResourcesList = Resources
                        .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(item => item.Trim())
                        .ToList();
                }
                else
                {
                    ResourcesList.Clear(); 
                }
            }
        }

    }
}
