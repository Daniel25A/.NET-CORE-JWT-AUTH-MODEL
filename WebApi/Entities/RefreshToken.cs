using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities;

public class RefreshToken
{
    public long Id { get; set; }
    [MaxLength(100)] public string JwtId { get; set; } = string.Empty;
    [MaxLength(350)] public string Token { get; set; } = string.Empty;
    public DateTime ExpireDate { get; set; }
    [MaxLength(100)] public string UserEmail { get; set; } = string.Empty;
}