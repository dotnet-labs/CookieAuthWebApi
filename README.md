# Cookie Authentication WebApi

> NOTE: This is a work in progress

## How to Get 401 HTTP Response

If you are interested, refer to issues [1](https://github.com/aspnet/Security/issues/1394), [2](https://github.com/dotnet/aspnetcore/issues/12842) and [3](https://github.com/aspnet/Security/issues/1541) on GitHub.

By default, when unauthenticated user tries to access a secured route, ASP.NET Core will redirect the request to `/Account/Login`, which is a default login endpoint. You can change this route by setting an option for cookie authentication. This is great for a routes returning views. However, we don't want that for web APIs. What we want is to return an HTTP Status `401 Unauthorized`.

In this case, we can configure the `OnRedirectToLogin` event by redirecting all normal requests to the login page, but for the API calls returning `401` status code. Then we can intercept this HTTP status code in our front-end application, and handle the error accordingly.

```CSharp
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.Cookie.SameSite = SameSiteMode.None;
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    options.Events.OnRedirectToLogin = context =>
                    {
                        if (context.Request.Path.StartsWithSegments("/api") && context.Response.StatusCode == (int)HttpStatusCode.OK)
                        {
                            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        }
                        else
                        {
                            context.Response.Redirect(context.RedirectUri);
                        }
                        return Task.CompletedTask;
                    };
                });

```
