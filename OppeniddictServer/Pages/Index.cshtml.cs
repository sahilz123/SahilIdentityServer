using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OppeniddictServer.Identity;

namespace OppeniddictServer.Pages
{
    public class IndexModel : PageModel
    {        
        public IndexModel()
        { 
        }
        public IActionResult OnGet()
        {     

            return Page();
        }
    }
}
