using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.UserRole
{
    public class IndexModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;
        public readonly RoleManager<UserIdentityRole> _roleManager;
        public readonly UserManager<UserIdentity> _userManager;

        public IndexModel(AdminIdentityDbContext context, RoleManager<UserIdentityRole> roleManager, UserManager<UserIdentity> userManager)
        {
            _context = context;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public List<UserRoleViewModel> UserRolesData { get; set; } = new List<UserRoleViewModel>();

        public IList<UserIdentityUserRole> UserIdentityUserRole { get;set; } = default!;
        public UserIdentity IdentityUser { get;set; } 
        public UserIdentityRole IdentityRole { get;set; }


        public async Task OnGetAsync()
        {
            if (_context.UserRoles != null)
            {
                UserIdentityUserRole = await _context.UserRoles.ToListAsync();

                foreach (IdentityUserRole<string> identityUserRole in UserIdentityUserRole)
                {
                    IdentityUser = await _userManager.FindByIdAsync(identityUserRole.UserId);
                    IdentityRole = await _roleManager.FindByIdAsync(identityUserRole.RoleId);

                    UserRolesData.Add(new UserRoleViewModel
                    {
                        UserName = IdentityUser.UserName,
                        Id = IdentityUser.Id,
                        Email = IdentityUser.Email,
                        RoleName = IdentityRole.Name
                    });

                }                
            
            }
        }

        public class UserRoleViewModel
        {
            public string Id { get; set; }
            public string Email { get; set; }
            public string UserName { get; set; }
            public string RoleName { get; set; }
        }
    }
}
