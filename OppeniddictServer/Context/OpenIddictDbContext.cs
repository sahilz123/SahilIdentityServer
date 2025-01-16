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
        //public DbSet<Client>? Client { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreApplication>? ApplicationManager { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreAuthorization>? Authorizations { get; set; }

        public DbSet<OpenIddictEntityFrameworkCoreScope>? ScopesManager { get; set; }
        public DbSet<OpenIddictEntityFrameworkCoreToken>? TokenManager { get; set; }



        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<OpenIddictEntityFrameworkCoreApplication>()
                  .HasDiscriminator<string>("Discriminator")
                  .HasValue<OpenIddictEntityFrameworkCoreApplication>("OpenIddictEntityFrameworkCoreApplication")
                  .HasValue<ApplicationManager>("Client");

            modelBuilder.Entity<OpenIddictEntityFrameworkCoreScope>()
                 .HasDiscriminator<string>("Discriminator")                                            
                 .HasValue<OpenIddictEntityFrameworkCoreScope>("OpenIddictEntityFrameworkCoreScope") 
                 .HasValue<ScopesManager>("ScopeManager");


            modelBuilder.Entity<OpenIddictEntityFrameworkCoreToken>()
                 .HasDiscriminator<string>("Discriminator")
                 .HasValue<OpenIddictEntityFrameworkCoreToken>("OpenIddictEntityFrameworkCoreToken")
                 .HasValue<TokenManager>("TokenManager");


            // Configure OpenIddict tables
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreApplication>().ToTable("OpenIddictApplications");
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreAuthorization>().ToTable("OpenIddictAuthorizations");
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreToken>().ToTable("OpenIddictTokens");
            modelBuilder.Entity<OpenIddictEntityFrameworkCoreScope>().ToTable("OpenIddictScopes");
        }

    }
}
