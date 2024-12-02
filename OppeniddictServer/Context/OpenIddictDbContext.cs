using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Openiddict;

namespace OppeniddictServer.Context
{
    public class OpenIddictDbContext : DbContext
    {

        public OpenIddictDbContext(DbContextOptions<OpenIddictDbContext> options) : base(options)
        { }

        // public DbSet<ClientData> ClientDbSet { get; set; }
        public DbSet<ApplicationManager>? ApplicationManager { get; set; }
        //public DbSet<OpenIddictEntityFrameworkCoreApplication>? Applications { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreAuthorization>? Authorizations { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreToken>? Tokens { get; set; }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure OpenIddict tables
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreApplication>(entity =>
            {
                entity.ToTable("OpenIddictApplications");
            });

            modelBuilder.Entity<OpenIddictEntityFrameworkCoreAuthorization>().ToTable("OpenIddictAuthorizations");
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreToken>().ToTable("OpenIddictTokens");
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreScope>().ToTable("OpenIddictScopes");
        }
    }
}
