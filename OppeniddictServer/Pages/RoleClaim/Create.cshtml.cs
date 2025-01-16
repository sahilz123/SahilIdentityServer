using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.RoleClaim
{
    public class CreateModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;
        public readonly RoleManager<UserIdentityRole> _roleManager;


        public CreateModel(AdminIdentityDbContext context, RoleManager<UserIdentityRole> roleManager)
        {
            _roleManager = roleManager;
            _context = context;
        }

        public IActionResult OnGet()
        {
            Role = _roleManager.Roles.ToList();

            return Page();
        }

        [BindProperty]
        public UserIdentityRoleClaim RoleClaim { get; set; } = default!;

        [BindProperty]
        public IList<UserIdentityRole> Role { get; set; } = default!;

        [BindProperty]
        public string SelectedRoleId { get; set; }=default!;

        [BindProperty]
        public UserIdentityRole SelectedRole { get; set; } = default!;

        public async Task<IActionResult> OnPostAsync()
        {

            SelectedRole = _roleManager.FindByIdAsync(SelectedRoleId).Result;

            if (SelectedRole is not null)
            {
                RoleClaim.RoleId = SelectedRoleId;

                if (!ModelState.IsValid || _context.RoleClaims == null || RoleClaim.RoleId == null || RoleClaim.ClaimValue == null)
                {
                    return Page();
                }

                var claim = new Claim(RoleClaim.ClaimType, RoleClaim.ClaimValue);
               

                await _roleManager.AddClaimAsync(SelectedRole!, claim);

                return RedirectToPage(Urls.Index);
            }
            return Page();
        }
    }
}
