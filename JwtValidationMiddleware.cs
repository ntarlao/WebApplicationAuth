csharp WebApplicationAuth/Middleware/JwtValidationMiddleware.cs
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using WebApplicationAuth.Infrastructure;

namespace WebApplicationAuth.Middleware
{
    public sealed class JwtValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<JwtValidationMiddleware> _logger;
        private readonly JwtSettings _settings;
        private readonly TokenValidationParameters _validationParameters;

        public JwtValidationMiddleware(RequestDelegate next, ILogger<JwtValidationMiddleware> logger, IOptions<JwtSettings> options)
        {
            _next = next;
            _logger = logger;
            _settings = options.Value;

            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SigningKey));
            _validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateIssuer = true,
                ValidIssuers = _settings.ValidIssuers,
                ValidateAudience = true,
                ValidAudiences = _settings.ValidAudiences,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            };
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();
                var handler = new JwtSecurityTokenHandler();
                try
                {
                    var principal = handler.ValidateToken(token, _validationParameters, out var validatedToken);

                    // Optional: further checks (e.g., specific claims, roles)
                    context.User = principal;
                }
                catch (SecurityTokenException ex)
                {
                    _logger.LogWarning(ex, "JWT validation failed.");
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new { error = "Invalid or expired token" });
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Unexpected error validating JWT.");
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    await context.Response.WriteAsJsonAsync(new { error = "Token validation error" });
                    return;
                }
            }

            await _next(context);
        }
    }
}