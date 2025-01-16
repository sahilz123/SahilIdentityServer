using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Constants;
using OppeniddictServer.Context;
using System.Xml.Linq;
using static OppeniddictServer.Pages.Scope.CreateModel;

namespace OppeniddictServer.Openiddict
{
    public class ScopesManager: OpenIddictEntityFrameworkCoreScope
    {
        private readonly OpenIddictDbContext _context;
        private readonly IOpenIddictScopeManager _manager;

        protected ScopesManager()
        {
            
        }
        public ScopesManager(OpenIddictDbContext context, IOpenIddictScopeManager manager)
        {
            _context = context;
            _manager = manager;
        }


        public async Task<string> CreateAsync(ScopeInputModel scope)
        {

            if (scope == null || string.IsNullOrEmpty(scope.Name))
            {
                throw new ArgumentNullException("Scope object or Name cannot be null");
            }

            var apiscope = await _manager.FindByNameAsync(scope.Name!);
            
            if (apiscope != null)
            {
                //await _manager.DeleteAsync(apiscope);
                return Constant.ScopeAlreadyExist;
            }
            var scopeDescriptor = new OpenIddictScopeDescriptor
            {
                Description = scope.Description ,
                DisplayName = scope.DisplayName ,
                Name = scope.Name ,
            };

            if (scope.ResourcesList?.Count > 0)
            {
                foreach (var resource in scope.ResourcesList)
                {
                    scopeDescriptor.Resources.Add(resource);
                }
            }

            await _manager.CreateAsync(scopeDescriptor);
            return Constant.ScopeCreated;
        }

        public async Task<List<OpenIddictEntityFrameworkCoreScope>> GetAvailableScopes()
        {      
        
            try
            {
                return await _context.ScopesManager!
                .Where(scope => scope.Name != null) 
                .ToListAsync();
                
            }
            catch
            {
                throw;
            }
        }

    }
}
