using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WebApi.Common;
using WebApi.Data;
using WebApi.Entities;
using WebApi.Models.Responses;

namespace WebApi.Services.Jwt
{
    public class Jwt : IJwt
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager;

        public Jwt(AppDbContext context, UserManager<User> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        public async Task<SignInResponse?> Login(string email, string password, CancellationToken token)
        {
            var user = await _context.Users.Include(x => x.Role)
                .FirstOrDefaultAsync(x => x.Email.Equals(email.Trim()), token);
            if (user is null)
                return null;
            var validPassword = await _userManager.CheckPasswordAsync(user, password);
            if (!validPassword)
                return null;
            return await GenerateAuthResult(user, token);
        }


        public async Task<SignInResponse?> RefreshToken(string refreshToken, CancellationToken token)
        {
            var validateToken = GetPrincipalFromToken(refreshToken);
            if (validateToken is null)
                return null;
            var expiryDateUnix =
                long.Parse(validateToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Exp).Value);
            var expiryDateUtc = DateTimeOffset.UnixEpoch.DateTime.AddSeconds(expiryDateUnix);
            if (DateTime.UtcNow > expiryDateUtc)
                return null;
            var tokenId = validateToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
            var refreshTokenModel = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.JwtId == tokenId, token);
            if (refreshTokenModel is null)
                return null;
            _context.RefreshTokens.Remove(refreshTokenModel);
            var user = await _userManager.FindByEmailAsync(refreshTokenModel.UserEmail);
            return await GenerateAuthResult(user, token);
        }


        private async Task<SignInResponse> GenerateAuthResult(User user, CancellationToken token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(JwtOptions.Instance.Secret);
            var refreshId = Guid.NewGuid();
            var claims = new List<Claim>()
            {
                new Claim("userId", user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role.Name ?? "NO TIENE NADA"),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("refreshId", refreshId.ToString()),
            };
            claims.AddRange(await _userManager.GetClaimsAsync(user));
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Audience = JwtOptions.Instance.Issuer,
                Issuer = JwtOptions.Instance.Issuer,
                Expires = DateTime.UtcNow.AddHours(5),
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var generateToken = tokenHandler.CreateToken(tokenDescriptor);
            var refreshTokenHandler = new JwtSecurityTokenHandler();

            var refreshTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Jti, refreshId.ToString())

                }),
                Audience = JwtOptions.Instance.Issuer,
                Issuer = JwtOptions.Instance.Issuer,
                Expires = DateTime.UtcNow.AddMonths(6),
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var refreshToken = refreshTokenHandler.CreateToken(refreshTokenDescriptor);
            var refreshTokenModel = new RefreshToken()
            {
                JwtId = refreshId.ToString(),
                ExpireDate = refreshTokenDescriptor.Expires.Value,
                Token = refreshTokenHandler.WriteToken(refreshToken),
                UserEmail = user.Email
            };
            _context.RefreshTokens.Add(refreshTokenModel);
            await _context.SaveChangesAsync(token);
            return new SignInResponse()
            {
                AccessToken = tokenHandler.WriteToken(generateToken),
                RefreshToken = refreshTokenModel.Token,
                UserId = user.Id
            };
        }

        private ClaimsPrincipal? GetPrincipalFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();

            try
            {
                var key = Encoding.ASCII.GetBytes(JwtOptions.Instance.Secret);
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                };
                var principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
                if (!IsJwtAlgorithmValid(validatedToken))
                    return null;
                return principal;
            }
            catch
            {
                return null;
            }
        }

        private static bool IsJwtAlgorithmValid(SecurityToken validatedToken)
        {
            return validatedToken is JwtSecurityToken jwtSecurityToken &&
                   jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                       StringComparison.InvariantCultureIgnoreCase);
        }
    }
}