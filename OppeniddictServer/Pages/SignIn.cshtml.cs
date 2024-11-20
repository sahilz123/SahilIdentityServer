using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Model;
using System.Web;

namespace OppeniddictServer.Pages
{
    public class SignInModel : PageModel
    {
        private readonly ClientSeeder _seeder;
        [BindProperty]
        public SignUp? SignUp { get; set; }
        public string? ResponseMessage { get; set; }


        public SignInModel(ClientSeeder seeder)
        {
            _seeder = seeder;
        }
        

        public void OnGet()
        {
            // Optional: Initialize default values here if needed
            SignUp = new SignUp();
        }

        public IActionResult OnPostAsync([FromForm]SignUp signUp)
        {
            if (ModelState.IsValid)
            {
                ResponseMessage = _seeder.AddClients(signUp).GetAwaiter().GetResult();
                return Page();
                //_seeder.AddScopes().GetAwaiter().GetResult();
            }
                return Page(); // Return the same page with validation errors
            
        }
    }
}
