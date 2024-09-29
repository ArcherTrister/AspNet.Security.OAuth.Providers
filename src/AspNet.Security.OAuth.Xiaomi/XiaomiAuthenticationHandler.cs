/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/ArcherTrister/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Xiaomi;

public partial class XiaomiAuthenticationHandler : OAuthHandler<XiaomiAuthenticationOptions>
{
    public XiaomiAuthenticationHandler(
        [NotNull] IOptionsMonitor<XiaomiAuthenticationOptions> options,
        [NotNull] ILoggerFactory logger,
        [NotNull] UrlEncoder encoder,
        [NotNull] ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    /// <inheritdoc />
    protected override string BuildChallengeUrl(
        [NotNull] AuthenticationProperties properties,
        [NotNull] string redirectUri)
    {
        string challengeUrl = base.BuildChallengeUrl(properties, redirectUri);

        // See https://dev.mi.com/distribute/doc/details?pId=1708
        // 默认值为true，授权有效期内的用户在已登录情况下，不显示授权页面，直接通过。如果需要用户每次手动授权，设置为false
        // 黄页应用接入请设置为true
        return QueryHelpers.AddQueryString(challengeUrl, "skip_confirm", Options.SkipConfirm.ToString());
    }

    protected override async Task<AuthenticationTicket> CreateTicketAsync(
        [NotNull] ClaimsIdentity identity,
        [NotNull] AuthenticationProperties properties,
        [NotNull] OAuthTokenResponse tokens)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["token"] = tokens.AccessToken,
            ["clientId"] = Options.ClientId
        };

        var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, parameters);

        using var response = await Backchannel.GetAsync(address, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            await Log.UserProfileErrorAsync(Logger, response, Context.RequestAborted);
            throw new HttpRequestException("An error occurred while retrieving user information.");
        }

        var json = await response.Content.ReadAsStringAsync(Context.RequestAborted);
        using var payload = JsonDocument.Parse(json);
        var rootElement = payload.RootElement;

        if (!rootElement.TryGetProperty("data", out JsonElement dataElement))
        {
            var errorCode = rootElement.GetString("code")!;
            throw new Exception($"An error (Code: {errorCode}) occurred while retrieving user information.");
        }

        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, dataElement.GetString("unionId")!, ClaimValueTypes.String, Options.ClaimsIssuer));

        var principal = new ClaimsPrincipal(identity);
        var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, dataElement);
        context.RunClaimActions();

        await Events.CreatingTicket(context);
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }

    private static partial class Log
    {
        [LoggerMessage(2, LogLevel.Error, "An error occurred while retrieving an access token with error {ErrorCode}: {Headers} {Body}.")]
        internal static partial void ExchangeCodeErrorCode(
            ILogger logger,
            string errorCode,
            string headers,
            string body);

        internal static async Task UserProfileErrorAsync(ILogger logger, HttpResponseMessage response, CancellationToken cancellationToken)
        {
            UserProfileError(
                logger,
                response.StatusCode,
                response.Headers.ToString(),
                await response.Content.ReadAsStringAsync(cancellationToken));
        }

        [LoggerMessage(4, LogLevel.Error, "An error occurred while retrieving retrieving the user profile with error {ErrorCode}: {Headers} {Body}.")]
        internal static partial void UserProfileErrorCode(
            ILogger logger,
            string errorCode,
            string headers,
            string body);

        [LoggerMessage(1, LogLevel.Error, "An error occurred while retrieving an access token: the remote server returned a {Status} response with the following payload: {Headers} {Body}.")]
        private static partial void ExchangeCodeError(
            ILogger logger,
            HttpStatusCode status,
            string headers,
            string body);

        [LoggerMessage(3, LogLevel.Error, "An error occurred while retrieving the user profile: the remote server returned a {Status} response with the following payload: {Headers} {Body}.")]
        private static partial void UserProfileError(
            ILogger logger,
            HttpStatusCode status,
            string headers,
            string body);
    }
}
