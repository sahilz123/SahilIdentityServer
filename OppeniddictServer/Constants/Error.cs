namespace OppeniddictServer.Constants
{
    public class Error
    {
        public const string PasswordMismatched = "Password Mismatched";
        public const string AuthenticateError = "Cannot authenticate - No user found with above Credentials";
        public const string ParameterError = "Parameter Mismatched or Invalid";
        public const string StatusFailed = "Failed";
        public const string InvalidCredential = "Invalid Credentials!!!";
        public const string ClientNotFound = "Details concerning the calling client application cannot be found.";
        public const string OpenIdException = "The OpenID Connect request cannot be retrieved.";
        public const string GrantTypeError = "The specified grant type is not supported.";
        public const string TokenInvalid = "The token is no longer valid.";

    }
}
