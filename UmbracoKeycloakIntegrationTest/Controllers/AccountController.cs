using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Umbraco.Cms.Core.Cache;
using Umbraco.Cms.Core.Logging;
using Umbraco.Cms.Core.Routing;
using Umbraco.Cms.Core.Security;
using Umbraco.Cms.Core.Services;
using Umbraco.Cms.Core.Web;
using Umbraco.Cms.Infrastructure.Persistence;
using Umbraco.Cms.Web.Common.Security;
using Umbraco.Cms.Web.Website.Controllers;
using AuthenticationProperties = Microsoft.AspNetCore.Authentication.AuthenticationProperties;

namespace UmbracoKeycloakIntegrationTest.Controllers
{
    public class AccountController : SurfaceController
    {
        private readonly IMemberManager _memberManager;
        private readonly IMemberService _memberService;
        private readonly IMemberSignInManager _memberSignInManager;

        public AccountController(
            IUmbracoContextAccessor umbracoContextAccessor,
            IUmbracoDatabaseFactory databaseFactory,
            ServiceContext services,
            AppCaches appCaches,
            IProfilingLogger profilingLogger,
            IPublishedUrlProvider publishedUrlProvider,
            IMemberManager memberManager,
            IMemberService memberService,
            IMemberSignInManager memberSignInManager)
            : base(umbracoContextAccessor, databaseFactory, services, appCaches, profilingLogger, publishedUrlProvider)
        {
            _memberManager = memberManager;
            _memberService = memberService;
            _memberSignInManager = memberSignInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Login(string? returnUrl)
        {
            var authenticationScheme = $"{Umbraco.Cms.Core.Constants.Security.MemberExternalAuthenticationTypePrefix}{KeycloakMemberExternalLoginProviderOptions.SchemeName}";
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(KeycloakLoginCallback)),
                Items = { { "returnUrl", returnUrl ?? "/" } }
            }, authenticationScheme);
        }

        public async Task<IActionResult> Logout()
        {
            await _memberSignInManager.SignOutAsync();

            return Redirect("~/");
        }

        [HttpGet]
        public async Task<IActionResult> KeycloakLoginCallback()
        {
            // load & validate the temporary cookie
            var result = await HttpContext.AuthenticateAsync("Identity.External");
            if (!result.Succeeded) throw new Exception("Missing external cookie");

            // auto-create account using email address
            var email = result.Principal.FindFirstValue(ClaimTypes.Email)
                        ?? result.Principal.FindFirstValue("email")
                        ?? throw new Exception("Missing email claim");

            MemberIdentityUser? user = await _memberManager.FindByEmailAsync(email);
            if (user == null)
            {
                _memberService.CreateMemberWithIdentity(email, email, email, "Member");
                user = await _memberManager.FindByNameAsync(email);
            }

            //in keycloak - builtin client role mapper have to be added and included in ID token with token claim name = roles
            await MergeUserRoles(result.Principal.FindAll(ClaimTypes.Role), user);

            // create the full membership session and cleanup the temporary cookie
            await HttpContext.SignOutAsync("Identity.External");
            await _memberSignInManager.SignInAsync(user, false);

            // basic open redirect defense
            var returnUrl = result.Properties?.Items.ContainsKey("returnUrl") == true
                ? result.Properties?.Items["returnUrl"]
                : null;
            if (returnUrl == null || !Url.IsLocalUrl(returnUrl)) returnUrl = "~/";

            return new RedirectResult(returnUrl);
        }

        private async Task MergeUserRoles(IEnumerable<Claim> userRoleClaimsFromProvider, MemberIdentityUser user)
        {
            var userRolesFromProvider = userRoleClaimsFromProvider.Select(x => x.Value).ToArray();
            var actualUserRoles = await _memberManager.GetRolesAsync(user);

            var rolesToRemove = actualUserRoles.Except(userRolesFromProvider);
            await _memberManager.RemoveFromRolesAsync(user, rolesToRemove);

            // role should be added automatically in umbraco as member group, even if it doesn't exist
            var rolesToAdd = userRolesFromProvider.Except(actualUserRoles);
            await _memberManager.AddToRolesAsync(user, rolesToAdd);
        }
    }
}