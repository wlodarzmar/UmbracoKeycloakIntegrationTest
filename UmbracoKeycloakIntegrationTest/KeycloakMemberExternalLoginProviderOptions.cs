﻿using Microsoft.Extensions.Options;
using Umbraco.Cms.Web.Common.Security;

namespace UmbracoKeycloakIntegrationTest
{

    public class KeycloakMemberExternalLoginProviderOptions : IConfigureNamedOptions<MemberExternalLoginProviderOptions>
    {
        public const string SchemeName = "Keycloak";

        public void Configure(string name, MemberExternalLoginProviderOptions options)
        {

            if (name != Umbraco.Cms.Core.Constants.Security.MemberExternalAuthenticationTypePrefix + SchemeName)
            {
                return;
            }

            Configure(options);
        }

        public void Configure(MemberExternalLoginProviderOptions options) =>
            options.AutoLinkOptions = new MemberExternalSignInAutoLinkOptions(
                // Must be true for auto-linking to be enabled
                autoLinkExternalAccount: true,

                // Optionally specify the default culture to create
                // the user as. If null it will use the default
                // culture defined in the web.config, or it can
                // be dynamically assigned in the OnAutoLinking
                // callback.
                defaultCulture: null,

                // Optionally specify the default "IsApprove" status. Must be true for auto-linking.
                defaultIsApproved: true,

                // Optionally specify the member type alias. Default is "Member"
                defaultMemberTypeAlias: "Member",

                // Optionally specify the member groups names to add the auto-linking user to.
                defaultMemberGroups: new[] { "partnerMembers" }

            )
            {
                // Optional callback
                OnAutoLinking = (autoLinkUser, loginInfo) =>
                {
                    // You can customize the member before it's linked.
                    // i.e. Modify the member's groups based on the Claims returned
                    // in the externalLogin info
                },
                OnExternalLogin = (user, loginInfo) =>
                {
                    // You can customize the member before it's saved whenever they have
                    // logged in with the external provider.
                    // i.e. Sync the member's name based on the Claims returned
                    // in the externalLogin info

                    return true; //returns a boolean indicating if sign in should continue or not.
                }
            };
    }
}
