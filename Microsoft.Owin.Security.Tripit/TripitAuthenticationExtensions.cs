// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.TripIt;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="TripItAuthenticationMiddleware"/>
    /// </summary>
    public static class TripItAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using TripIt
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseTripItAuthentication(this IAppBuilder app, TripItAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(TripItAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using TripIt
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by TripIt</param>
        /// <param name="appSecret">The appSecret assigned by TripIt</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseTripItAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseTripItAuthentication(
                app,
                new TripItAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret,
                });
        }
    }
}
