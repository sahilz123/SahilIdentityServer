using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.UserRole
{
    public class EditModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;
        private readonly UserManager<UserIdentity> _userManager;
        public EditModel(AdminIdentityDbContext context ,UserManager<UserIdentity> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [BindProperty]
        public UserIdentityUserRole UserIdentityUserRole { get; set; } = default!;
                
        [BindProperty]
        public string UserName { get; set; } = default!;
        

        public IList<IdentityRole> AvailableRoles { get; set; } = new List<IdentityRole>();
       
        [BindProperty]
        public List<string> SelectedRoles { get; set; } = new List<string>();
        public async Task<IActionResult> OnGetAsync(string id)
        {
            if (id == null || _context.UserRoles == null)
            {
                return NotFound();
            }

            // Get UserRole relationship
            var useridentityuserrole = await _context.UserRoles.FirstOrDefaultAsync(m => m.UserId == id);
            if (useridentityuserrole == null)
            {
                return NotFound();
            }

            UserIdentityUserRole = useridentityuserrole;
            UserName = _userManager.FindByIdAsync(id).Result.NormalizedUserName.ToString();

            // Load all available roles
           var rolesAvailable = await _context.Roles.ToListAsync();

            foreach(var roles in rolesAvailable)
            {
                AvailableRoles.Add(roles);
            }
            SelectedRoles = _context.UserRoles
                            .Where(ur => ur.UserId == id)
                            .Select(ur => ur.RoleId)
                            .ToList();

            return Page();
        }


        public async Task<IActionResult> OnPostAsync()
        {
            ModelState.Remove(nameof(UserName));

            if (!ModelState.IsValid)
            {
                return Page();
            }

            try{
                var existingRoles = _context.UserRoles.Where(ur => ur.UserId == UserIdentityUserRole.UserId).ToList();
                _context.UserRoles.RemoveRange(existingRoles);

                foreach (var roleId in SelectedRoles)
                {
                    _context.UserRoles.Add(new UserIdentityUserRole
                    {
                        UserId = UserIdentityUserRole.UserId,
                        RoleId = roleId
                    });
                }

                await _context.SaveChangesAsync();
            }
            catch { throw; };

            return RedirectToPage("./Index");
        }
    }
}
