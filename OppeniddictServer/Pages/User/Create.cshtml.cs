using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
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

        public IList<IdentityRole> AvailableRoles { get; set; } = new List<IdentityRole>();
        public Dictionary<string, List<string>> AvailableClaimsBasedOnRoles { get; set; } = new();
        public async Task<IActionResult> OnGet()
        {
            
            var rolesAvailable = await _context.Roles.ToListAsync();

            foreach (var roles in rolesAvailable)
            {
                AvailableRoles.Add(roles);

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
        public List<string> SelectedClaims { get; set; } =new List<string>();
        
        [BindProperty]
        public string UniqueClaims { get; set; } =default!;

        public List<string> UniqueClaimsList { get; set; } =new List<string>();

        public async Task<IActionResult> OnPostAsync()
        {
            var s = SelectedClaims;         //claims selected by roles
           
            if (!string.IsNullOrWhiteSpace(UniqueClaims))
            {
                UniqueClaimsList = UniqueClaims.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                         .Select(word => word.Trim())
                                         .ToList();
            }

            var u = UniqueClaimsList;   //claims of users other than the roles-claim
            UserIdentity.Id = Guid.NewGuid().ToString();

            if (!ModelState.IsValid ||  UserIdentity == null)
            {
                
                return Page();
            }
            var user = await _userManager.FindByNameAsync(UserIdentity.UserName)
                                ?? await _userManager.FindByEmailAsync(UserIdentity.Email);
            if (user != null) return Page();

            var Password=UserIdentity.UserName+UserIdentity.Email;          //return to the user so that they can
                                                                            //logged in with the given password

            var claims = new List<Claim>();

            foreach (var p in SelectedClaims)
            {
               claims.Add( new Claim("Permission", p));
            }
            
            foreach (var p in UniqueClaimsList)
            {
               claims.Add( new Claim("ClaimsByUser", p));
            }
                
        

            var result = await _userManager.CreateAsync(UserIdentity, Password);

            if (result.Succeeded)
            {
                await _userManager.AddClaimsAsync(UserIdentity,claims);
                foreach (var role in AssignedRoles) { await _userManager.AddToRoleAsync(UserIdentity, role); }

                return RedirectToPage("./Index");
            }
            return Page();
        }

    }
}
