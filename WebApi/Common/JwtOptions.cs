namespace WebApi.Common;

public class JwtOptions
{
    public static readonly JwtOptions Instance = new JwtOptions();
    private JwtOptions()
    {
        Expiration = TimeSpan.FromMinutes(5);
        RefreshExpiration = TimeSpan.FromDays(30);
        Secret = "<KEY HERE>";
        Issuer = "https://www.yoursite.com";
    }
        
    public TimeSpan Expiration { get; }
    public TimeSpan RefreshExpiration { get; }
    public string Secret { get; }
    public string Issuer { get; }
}