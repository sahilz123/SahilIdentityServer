using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly SignInManager<UserIdentity> _signInManager;
        private readonly UserManager<UserIdentity> _userManager;

        public IndexModel(ILogger<IndexModel> logger, SignInManager<UserIdentity> signInManager, UserManager<UserIdentity> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        
            _logger = logger;
        }
        public IActionResult OnGet()
        {
            //if (!User.Identity.IsAuthenticated)
            //{
            //    return Redirect("~/ServerLogin");
            //}

            return Page();
        }
    }
}
