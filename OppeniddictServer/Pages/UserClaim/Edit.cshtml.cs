using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.UserClaim
{
    public class EditModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly AdminIdentityDbContext _context;

        public EditModel(UserManager<UserIdentity> userManager, AdminIdentityDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        [BindProperty]
        public UserIdentityUserClaim UserIdentityUserClaim { get; set; } = default!;

        [BindProperty]
        public UserIdentity UserIdentity { get; set; } = default!;

        public  IActionResult OnGet(int? id)
        {            
            var useridentityuserclaim = _context.UserClaims.FirstOrDefault(m => m.Id == id);

            if (useridentityuserclaim == null)
            {
                return NotFound();
            }
            UserIdentityUserClaim = useridentityuserclaim;           
            return Page();
        }
               
        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                
                var userClaim = _context.UserClaims.FirstOrDefault(m => m.Id == UserIdentityUserClaim.Id);      //old claims of the selected user

                UserIdentity = await _userManager.FindByIdAsync(UserIdentityUserClaim.UserId);                          //new claims of the selected user

                Claim oldclaim=new(userClaim!.ClaimType, userClaim.ClaimValue);

                Claim newclaim=new(UserIdentityUserClaim.ClaimType, UserIdentityUserClaim.ClaimValue);
            
                await _userManager.ReplaceClaimAsync(UserIdentity, oldclaim,newclaim);                                  //replacing value of claims
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserIdentityUserClaimExists(UserIdentityUserClaim.Id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return RedirectToPage(Urls.Index);
        }

        private bool UserIdentityUserClaimExists(int id)
        {
          return (_context.UserClaims?.Any(e => e.Id == id)).GetValueOrDefault();
        }
    }
}
