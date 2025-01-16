using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.UserRole
{
    public class CreateModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;

        public CreateModel(AdminIdentityDbContext context)
        {
            _context = context;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        [BindProperty]
        public UserIdentityUserRole UserIdentityUserRole { get; set; } = default!;

        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.UserRoles == null || UserIdentityUserRole == null)
            {
                return Page();
            }

            _context.UserRoles.Add(UserIdentityUserRole);
            await _context.SaveChangesAsync();

            return RedirectToPage(Urls.Index);
        }
    }
}
