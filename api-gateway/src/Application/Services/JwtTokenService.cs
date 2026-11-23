using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace Bizcord.ApiGateway.Services;

public class CreateTokenOptions
{
    public Dictionary<string, string> Claims { get; set; } = new();
    public string? Audience { get; set; }
}

public class JwtTokenService
{
    private readonly string AuthenticationProviderKey;

    public JwtTokenService(string authenticationProviderKey)
    {
        AuthenticationProviderKey = authenticationProviderKey;
    }

    public AuthenticationToken CreateToken(CreateTokenOptions options)
    {
        var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AuthenticationProviderKey));
        var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>();
        foreach (var claim in options.Claims)
        {
            if (claim.Key == "sub")
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Sub, claim.Value));
                continue;
            }
            claims.Add(new Claim(claim.Key, claim.Value));
        }

        var tokenOptions = new JwtSecurityToken(
            issuer: "MicroserviceSI",
            audience: options.Audience ?? "NotificationService",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: signingCredentials
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        return new AuthenticationToken { Value = tokenString };
    }
}
