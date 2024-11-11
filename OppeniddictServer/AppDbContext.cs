using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.EntityFrameworkCore;
using OppeniddictServer.ClientManager;

namespace OppeniddictServer
{
    public class AppDbContext:DbContext
    {

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        { }          

        public DbSet<ClientData> ClientDbSet { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ClientData>(e => e.ToTable("ClientDetails").HasKey("Client_Id")) ;
            modelBuilder.Entity<ClientData>(entity =>
            {
                entity.Property(e => e.Client_Id).IsRequired().HasColumnName("CLient_Id");
                entity.Property(e => e.ClientEmail).IsRequired().HasColumnName("ClientEmail");
                entity.Property(e => e.ClientPassword).IsRequired().HasColumnName("ClientPassword");
                entity.Property(e => e.ClientUsername).IsRequired().HasColumnName("ClientUsername");
                entity.Property(e => e.ClientRole).IsRequired().HasColumnName("ClientRole");

            });

            base.OnModelCreating(modelBuilder);
        }
    }
}
