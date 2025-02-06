using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages.UserClaim
{
    public class CreateModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;


        public CreateModel(UserManager<UserIdentity> userManager)
        {
            _userManager = userManager;
        }

        [BindProperty]
        public List<UserIdentity> UserAvailable { get; set; } = default!;

        [BindProperty]
        public string SelectedUser { get; set; } = default!;

        
        public IActionResult OnGet()
        {
            UserAvailable = _userManager.Users.ToList();
            SelectedUser = UserAvailable.FirstOrDefault()!.Id!;

            return Page();
        }

        [BindProperty]
        public UserIdentityUserClaim UserIdentityUserClaim { get; set; } = default!;
        
        public async Task<IActionResult> OnPostAsync()
        {
          if (!ModelState.IsValid ||  UserIdentityUserClaim == null)
            {
                return Page();
            }
           
            Claim cl=new(UserIdentityUserClaim.ClaimType, UserIdentityUserClaim.ClaimValue);

            var user = _userManager.Users.FirstOrDefault(x=>x.Id==SelectedUser);
            if (user!=null)
            { await _userManager.AddClaimAsync(user, cl); }
            else
            {
                return BadRequest();
            }

            return RedirectToPage(Urls.Index);
        }
    }
}
