namespace OppeniddictServer.Model
{
    public class RegisterInput
    {
        public string? ClientId { get; set; }
        public string? DisplayName { get; set; }
        public string? RedirectUris { get; set; }
        public string? Permissions { get; set; }
        public List<string>? Scopes { get; set; }
    }
}
