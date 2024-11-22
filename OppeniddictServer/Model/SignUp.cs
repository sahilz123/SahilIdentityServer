namespace OppeniddictServer.Model
{
    public class RegisterInput
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
        public int? ClientId { get; set; }
        public string? DisplayName { get; set; }
        public string? RedirectUris { get; set; }
        public string? Permissions { get; set; }
    }
}
