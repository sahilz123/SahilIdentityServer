using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.Role
{
    [Authorize(Roles = "User")]
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
        public UserIdentityRole UserIdentityRole { get; set; } = default!;
        
        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid || _context.Roles == null || UserIdentityRole == null)
            {
                return Page();
            }
            UserIdentityRole.NormalizedName = UserIdentityRole.Name.ToUpper();

            _context.Roles.Add(UserIdentityRole);
            await _context.SaveChangesAsync();

            return RedirectToPage("./Index");
        }
    }
}
