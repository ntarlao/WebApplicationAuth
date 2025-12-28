namespace WebApplicationAuth.Middleware
{
    public static class JwtValidationMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtValidation(this IApplicationBuilder app)
        {
            return app.UseMiddleware<JwtValidationMiddleware>();
        }
    }
}