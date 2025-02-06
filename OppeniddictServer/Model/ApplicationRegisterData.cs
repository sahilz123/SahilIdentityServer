namespace OppeniddictServer.Model
{
    public class ApplicationRegisterData
    {
        public string? ClientId { get; set; }
        public string? ClientType { get; set; }
        public string? ConsentType { get; set; }
        public string? DisplayName { get; set; }
        public string? Properties { get; set; }
        public List<string>? RedirectUris { get; set; }//= new List<string>();
        public List<string>? Permissions { get; set; } = new List<string>();
        public List<string>? Scopes { get; set; } = new List<string>();
        public List<string>? PostLogoutRedirectUris { get; set; }//= new List<string>();
    }


}
