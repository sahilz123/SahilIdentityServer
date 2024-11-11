using OppeniddictServer.ClientManager;

namespace OppeniddictServer.Interface
{
    public interface IClientService
    {
        public Task<ClientData> GetClientList(string email, string password);
    }
}
