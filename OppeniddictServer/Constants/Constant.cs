namespace OppeniddictServer.Constants
{
    static class Constant
    {
        public const string Email = "Email";
        public const string Password = "Password";

        public const string DenyAccessValue = "Deny";
        public const string GrantAccessValue = "Grant";

        public const string ConsentNaming = "Consent";

        public const string ClientAlreadyExist= "Client Already Exist";
        public const string ScopeAlreadyExist= "Scope Already Existed";
        public const string ScopeCreated= "Scope Created";


        public const string ClaimsByUser= "ClaimsByUser";
               

    }

    static class Register
    {
        public const string PasswordsDoNotMatch = "Passwords do not match.";
        public const string EmailAlreadyTaken = "Email is already taken.";

    }

    static class Roles
    {
        public const string User = "User";
        public const string Admin = "Admin";
        public const string SuperAdmin = "SuperAdmin";
        public const string Manager = "Manager";

    }

    static class Urls
    {
        public const string ConsentWithReturnUrl = "/Consent?returnUrl=";
        public const string Index = "./Index";
        public const string Home = "https://localhost:7000";
        public const string ServerLogin = "/ServerLogin";
        public const string Error = "/Error";
    }
}
