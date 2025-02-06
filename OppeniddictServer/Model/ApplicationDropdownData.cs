using Microsoft.AspNetCore.Mvc.Rendering;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OppeniddictServer.Model
{
    public class ApplicationDropdownData
    {
        public static List<SelectListItem> GetPermissions()
        {
            var g1 = new SelectListGroup() { Name = "Endpoints" };
            var g2 = new SelectListGroup() { Name = "GrantTypes" };
            var g3 = new SelectListGroup() { Name = "Permission-Scopes" };
            var g4 = new SelectListGroup() { Name = "ResponseType" };
            var g5 = new SelectListGroup() { Name = "Scope" };

            // Language List
            var permission = new List<SelectListItem>
        {
            new () { Text = "Authorization", Value = Permissions.Endpoints.Authorization, Group = g1    },
            new () { Text = "Device", Value = Permissions.Endpoints.Device, Group = g1},
            new() { Text = "Revocation", Value = Permissions.Endpoints.Revocation, Group = g1 },
            new() { Text = "Token", Value = Permissions.Endpoints.Token, Group = g1 },
            new() { Text = "Logout", Value = Permissions.Endpoints.Logout, Group = g1 },

            new() { Text = "AuthorizationCode", Value = Permissions.GrantTypes.AuthorizationCode, Group = g2 },
            new() { Text = "ClientCredentials", Value = Permissions.GrantTypes.RefreshToken, Group = g2 },
            new() { Text = "DeviceCode", Value = Permissions.GrantTypes.RefreshToken, Group = g2 },
            new() { Text = "Implicit", Value = Permissions.GrantTypes.RefreshToken, Group = g2 },

            new() { Text = "Email", Value = Permissions.Scopes.Email, Group = g3 },
            new() { Text = "Roles", Value = Permissions.Scopes.Roles, Group = g3 },
            new() { Text = "Address", Value = Permissions.Scopes.Address, Group = g3 },
            new() { Text = "Profile", Value = Permissions.Scopes.Profile, Group = g3 },
            new() { Text = "Phone", Value = Permissions.Scopes.Phone, Group = g3 },

            new() { Text = "Code", Value = Permissions.ResponseTypes.Code, Group = g4 },
            new() { Text = "CodeToken", Value = Permissions.ResponseTypes.CodeToken, Group = g4 },
            new() { Text = "CodeIdToken", Value = Permissions.ResponseTypes.CodeIdToken, Group = g4 },
            new() { Text = "Token", Value = Permissions.ResponseTypes.Token, Group = g4 },

            new() { Text = "OpenId", Value = Scopes.OpenId, Group = g5 },
            new() { Text = "OfflineAccess", Value = Scopes.OfflineAccess, Group = g5 },


        };

            return permission;
        }
        
        public static List<SelectListItem> GetClientType()
        {
            var type = new List<SelectListItem>
        {
            new () { Text = "Confidential", Value = ClientTypes.Confidential},
            new () { Text = "Public", Value = ClientTypes.Public},
            

        };

            return type;
        }
        
        public static List<SelectListItem> GetConsentType()
        {
            var consent = new List<SelectListItem>
        {
            new () { Text = "Explicit", Value = ConsentTypes.Explicit},
            new () { Text = "External", Value = ConsentTypes.External},
            new () { Text = "Implicit", Value = ConsentTypes.Implicit},
            //new () { Text = "Systematic", Value = ConsentTypes.Systematic},
            
        };

            return consent;
        }
    }
}
