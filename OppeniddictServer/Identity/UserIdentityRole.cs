using Microsoft.AspNetCore.Identity;

namespace OppeniddictServer.Identity
{
	public class UserIdentityRole : IdentityRole
	{
        public UserIdentityRole()
        {            
        }

    }
    public static class SeedRoles
    {
        public static async Task Initialize(IServiceProvider serviceProvider, RoleManager<UserIdentityRole> roleManager)
        {
            string[] roleNames = { "Admin", "User", "Manager" };

            foreach (var roleName in roleNames)
            {
                var roleExist = await roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    var role = new UserIdentityRole { Name = roleName };
                    await roleManager.CreateAsync(role);
                }
            }
        }
    }


}