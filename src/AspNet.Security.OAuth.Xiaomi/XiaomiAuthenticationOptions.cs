/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/ArcherTrister/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Security.Claims;
using static AspNet.Security.OAuth.Xiaomi.XiaomiAuthenticationConstants;

namespace AspNet.Security.OAuth.Xiaomi;

/// <summary>
/// Defines a set of options used by <see cref="XiaomiAuthenticationHandler"/>.
/// </summary>
public class XiaomiAuthenticationOptions : OAuthOptions
{
    public XiaomiAuthenticationOptions()
    {
        ClaimsIssuer = XiaomiAuthenticationDefaults.Issuer;
        CallbackPath = XiaomiAuthenticationDefaults.CallbackPath;

        AuthorizationEndpoint = XiaomiAuthenticationDefaults.AuthorizationEndpoint;
        TokenEndpoint = XiaomiAuthenticationDefaults.TokenEndpoint;
        UserInformationEndpoint = XiaomiAuthenticationDefaults.UserInformationEndpoint;

        SkipConfirm = true;

        ClaimActions.MapJsonKey(ClaimTypes.Name, "miliaoNick");
        ClaimActions.MapJsonKey(Claims.MiliaoNick, "miliaoNick");
        ClaimActions.MapJsonKey(Claims.UnionId, "unionId");
        ClaimActions.MapJsonKey(Claims.MiliaoIcon, "miliaoIcon");
    }

    /// <summary>
    /// See https://dev.mi.com/distribute/doc/details?pId=1708
    /// 默认值为true，授权有效期内的用户在已登录情况下，不显示授权页面，直接通过。如果需要用户每次手动授权，设置为false
    /// 黄页应用接入请设置为true
    /// </summary>
    public bool SkipConfirm { get; set; }
}
