using Microsoft.EntityFrameworkCore;
using OppeniddictServer.Interface;

namespace OppeniddictServer.ClientManager
{
    public class ClientService : IClientService
    {
        protected readonly AppDbContext Context;
        protected readonly DbContextOptions<AppDbContext> dbContextOptions;

        public ClientService(AppDbContext context, DbContextOptions<AppDbContext> options)
        {
            Context = context;
            dbContextOptions = options;
        }

        public async Task<ClientData?> GetClientList(string email, string password)         //get all client that are saved into the database and matches there roles with the email id
        {
            try
            {
                using (var db = new AppDbContext(dbContextOptions))
                {
                    return await db.ClientDbSet
                                   .Where(c => c.ClientEmail == email && c.ClientPassword == password)
                                   .SingleOrDefaultAsync() ;
                }
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                return null;
            }
        }
    }
}
