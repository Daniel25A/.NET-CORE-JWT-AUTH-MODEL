using WebApi.Common;
using WebApi.Models.Responses;

namespace WebApi.Services.Jwt;

public interface IJwt
{
    Task<SignInResponse?> Login(string email, string password, CancellationToken token);
    Task<SignInResponse?> RefreshToken(string refreshToken, CancellationToken token);
}