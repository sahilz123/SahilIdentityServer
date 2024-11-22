using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Identity;
using OppeniddictServer.Model;
using System.Web;

namespace OppeniddictServer.Pages
{
    public class SignInModel : PageModel
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly SignInManager<UserIdentity> _signInManager;
        private readonly ClientSeeder _seeder;
       
        [BindProperty]
        public RegisterInput? RegisterInput { get; set; }
        public string? ResponseMessage { get; set; }


        public SignInModel(ClientSeeder seeder, UserManager<UserIdentity> userManager,SignInManager<UserIdentity> signInManager)
        {
            _seeder = seeder;
            _userManager = userManager;
            _signInManager = signInManager;
        }
        

        public void OnGet()
        {
            // Optional: Initialize default values here if needed
            RegisterInput = new RegisterInput();
        }

        public IActionResult OnPostAsync([FromForm]RegisterInput RegisterInput)
        {
            if (ModelState.IsValid)
            {
                ResponseMessage = _seeder.AddClients(RegisterInput).GetAwaiter().GetResult();
                return Page();
                //_seeder.AddScopes().GetAwaiter().GetResult();
            }



            return Page(); // Return the same page with validation errors
            
        }
    }
}
