using System.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.User
{
    public class CreateModel : PageModel
    {
        private readonly AdminIdentityDbContext _context;
        private readonly UserManager<UserIdentity> _userManager;
        public readonly RoleManager<UserIdentityRole> _roleManager;


        public CreateModel(AdminIdentityDbContext context,UserManager<UserIdentity> userManager, RoleManager<UserIdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
        }

        
        [BindProperty]
        public List<string> AvailableRolesNames { get; set; } = new List<string>();
        
        [BindProperty]
        public Dictionary<string, List<string>> AvailableClaimsBasedOnRoles { get; set; } = new();
        public async Task<IActionResult> OnGet()
        {
            
            var rolesAvailable = await _context.Roles.ToListAsync();

            foreach (var roles in rolesAvailable)
            {
                AvailableRolesNames.Add(roles.Name);

                var claims = await _roleManager.GetClaimsAsync(roles);

                var claimNames = claims.Select(c => c.Value).ToList();

                AvailableClaimsBasedOnRoles[roles.Name] = claimNames;
            }

            return Page();
        }

        [BindProperty]
        public UserIdentity UserIdentity { get; set; } = default!;
        
        [BindProperty]
        public List<string> AssignedRoles { get; set; } =new List<string>();
       
        
        [BindProperty]
        public List<string> SelectedClaims { get; set; } =new List<string>();       //all claims provided by the user

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid || UserIdentity == null)
            {

                return Page();
            }
            
            var user = await _userManager.FindByNameAsync(UserIdentity.UserName)
                                ?? await _userManager.FindByEmailAsync(UserIdentity.Email);
            if (user != null) return Page();

            var Password=UserIdentity.UserName.ToUpper() + UserIdentity.Email+1;          //return to the user so that they can
                                                                                        //logged in with the given password

            var claims = new List<Claim>();

            foreach (var p in SelectedClaims)
            {
               claims.Add( new Claim(Constant.ClaimsByUser, p));
            }
          
            var result = await _userManager.CreateAsync(UserIdentity, Password);

            if (result.Succeeded)
            {
                await _userManager.AddClaimsAsync(UserIdentity,claims);
                //var existingClaims = await _userManager.GetClaimsAsync(UserIdentity);


                foreach (var role in AssignedRoles) { await _userManager.AddToRoleAsync(UserIdentity, role); }

                await _userManager.UpdateAsync(UserIdentity);

                return RedirectToPage(Urls.Index);
            }
            return Page();
        }

    }
}
