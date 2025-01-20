using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.Constants;
using static OppeniddictServer.Pages.Scope.CreateModel;

namespace OppeniddictServer.Openiddict
{
    public class ScopesManager: OpenIddictEntityFrameworkCoreScope
    {
        private readonly IOpenIddictScopeManager _manager;

        protected ScopesManager()
        {

        }
        public ScopesManager( IOpenIddictScopeManager manager)
        {
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

            if (scope.Resources?.Count > 0)
            {
                foreach (var resource in scope.Resources)
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
                var scopes = new List<OpenIddictEntityFrameworkCoreScope>();

                await foreach (var scope in _manager.ListAsync())
                {
                    if (scope is OpenIddictEntityFrameworkCoreScope efScope)
                    {
                        scopes.Add(efScope);
                    }
                }

                return scopes;
            }
            catch
            {
                throw;
            }
        }

    }
}
