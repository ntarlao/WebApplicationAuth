namespace WebApplicationAuth.Infrastructure
{
    public sealed class JwtSettings
    {
        public string SigningKey { get; set; } = "ReplaceWithAStrongSigningKey_AtLeast_32CharsLong!";
        public string Issuer { get; set; } = "WebApplicationAuthIssuer";
        public string[] ValidAudiences { get; set; } = new string[] { "WebApplicationAuthClient" };
        public string[] ValidIssuers { get; set; } = new string[] { "WebApplicationAuthIssuer" };
        public int TokenExpiryMinutes { get; set; } = 60;
    }
}