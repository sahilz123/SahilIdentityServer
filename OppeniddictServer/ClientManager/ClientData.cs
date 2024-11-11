namespace OppeniddictServer.ClientManager
{
    public class ClientData
    {
        public string? Client_Id { get; set; }
        public string? ClientEmail { get; set; }
        public string? ClientPassword { get; set; }
        public string? ClientUsername { get; set; }
        public RoleType ClientRole { get; set; }
    }

    public enum RoleType
    {
       Guest, Admin, User
    }
}
