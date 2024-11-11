Implement OpenIddict for Token Generation and Validation

Integrated OpenIddict server on port 7000 to handle authorization and token generation.
Configured OpenIddict to expose the following endpoints:
Authorization Endpoint: /authorize
Token Endpoint: /token
OpenID Connect discovery document: /.well-known/openid-configuration
Added symmetric encryption for secure token generation.
Set up OpenIddict Validation on the resource server (port 7002) to validate tokens issued by the identity server on port 7000.
Configured the validation middleware to retrieve the issuer and discovery metadata from the identity server at https://localhost:7000/.
Ensured correct audience validation and integration with ASP.NET Core authentication.
This setup enables secure token-based communication between the resource server (7002) and the identity server (7000).
