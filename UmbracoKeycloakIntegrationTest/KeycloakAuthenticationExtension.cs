using AspNet.Security.OAuth.Keycloak;

namespace UmbracoKeycloakIntegrationTest
{
    public static class KeycloakAuthenticationExtension
    {
        public static IUmbracoBuilder AddMemberKeycloakAuthentication(this IUmbracoBuilder builder)
        {
            
            builder.Services.ConfigureOptions<KeycloakMemberExternalLoginProviderOptions>();

            builder.AddMemberExternalLogins(logins =>
            {
                logins.AddMemberLogin(
                    memberAuthenticationBuilder =>
                    {
                        memberAuthenticationBuilder.AddKeycloak(
                            // The scheme must be set with this method to work for the umbraco members
                            memberAuthenticationBuilder.SchemeForMembers("UmbracoMembers.Keycloak"),
                            options =>
                            {
                                options.AccessType = KeycloakAuthenticationAccessType.Confidential;
                                options.BaseAddress = new Uri("http://localhost:8080/");
                                options.Domain = "http://localhost:8080/";
                                options.Realm = "MyTestLocalRealm";
                                options.ClientId = "umbracoLocalTest";
                                options.ClientSecret = "cywWTElC4jojVbfajXwPdZaQZCbv6f4P";
                            });
                    });
            });
            return builder;
        }
    }
}
