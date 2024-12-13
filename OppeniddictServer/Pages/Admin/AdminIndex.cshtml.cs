using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using System.Threading.Tasks;

//[Authorize(Policy = "AdminPolicy")]
public class AdminIndexModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    //private readonly RoleManager<IdentityRole> _roleManager;
    //private readonly UserManager<IdentityUser> _userManager;

    public AdminIndexModel(
                    IOpenIddictApplicationManager applicationManager,
                    IOpenIddictScopeManager scopeManager
                    //RoleManager<IdentityRole> roleManager,
                    //UserManager<IdentityUser> userManager
                    )
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        //_roleManager = roleManager;
        //_userManager = userManager;
    }

    [BindProperty]
    public string NewClientId { get; set; }
    [BindProperty]
    public string NewClientSecret { get; set; }
    [BindProperty]
    public string NewRoleName { get; set; }
    [BindProperty]
    public string NewScopeName { get; set; }
    [BindProperty]
    public string SelectedUserId { get; set; }
    [BindProperty]
    public string SelectedRoleName { get; set; }

    public async Task<IActionResult> OnPostAddClientAsync()
    {
        await _applicationManager.CreateAsync(new OpenIddictEntityFrameworkCoreApplication
        {
            ClientId = NewClientId,
            ClientSecret = NewClientSecret,
            DisplayName = "New Client",
            //Permissions = { OpenIddictConstants.Permissions.Endpoints.Token }
        });
        return Redirect("/Role");
    }

    public async Task<IActionResult> OnPostAddRoleAsync()
    {
        //var role = new IdentityRole(NewRoleName);
        //await _roleManager.CreateAsync(role);
        return Redirect("/Role");
    }

    public async Task<IActionResult> OnPostAddScopeAsync()
    {
        await _scopeManager.CreateAsync(new OpenIddictEntityFrameworkCoreScope
        {
            Name = NewScopeName,
            DisplayName = "New Scope"
        });
        return Redirect("/Role");
    }

    public async Task<IActionResult> OnPostAssignUserRoleAsync()
    {
        //var user = await _userManager.FindByIdAsync(SelectedUserId);
        //if (user != null)
        //{
        //    await _userManager.AddToRoleAsync(user, SelectedRoleName);
        //}
        return Redirect("/Role");
    }
}
