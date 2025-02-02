﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/ArcherTrister/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OAuth.Xiaomi;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods to add Xiaomi authentication capabilities to an HTTP application pipeline.
/// </summary>
public static class XiaomiAuthenticationExtensions
{
    /// <summary>
    /// Adds <see cref="XiaomiAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Xiaomi authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthenticationBuilder AddXiaomi([NotNull] this AuthenticationBuilder builder)
    {
        return builder.AddXiaomi(XiaomiAuthenticationDefaults.AuthenticationScheme, options => { });
    }

    /// <summary>
    /// Adds <see cref="XiaomiAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Xiaomi authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static AuthenticationBuilder AddXiaomi(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] Action<XiaomiAuthenticationOptions> configuration)
    {
        return builder.AddXiaomi(XiaomiAuthenticationDefaults.AuthenticationScheme, configuration);
    }

    /// <summary>
    /// Adds <see cref="XiaomiAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Xiaomi authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Xiaomi options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddXiaomi(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme,
        [NotNull] Action<XiaomiAuthenticationOptions> configuration)
    {
        return builder.AddXiaomi(scheme, XiaomiAuthenticationDefaults.DisplayName, configuration);
    }

    /// <summary>
    /// Adds <see cref="XiaomiAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Xiaomi authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="caption">The optional display name associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Xiaomi options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddXiaomi(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme,
        [CanBeNull] string caption,
        [NotNull] Action<XiaomiAuthenticationOptions> configuration)
    {
        return builder.AddOAuth<XiaomiAuthenticationOptions, XiaomiAuthenticationHandler>(scheme, caption, configuration);
    }
}
