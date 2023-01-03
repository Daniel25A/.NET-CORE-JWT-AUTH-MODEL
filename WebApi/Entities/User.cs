using Microsoft.AspNetCore.Identity;

namespace WebApi.Entities;

public class User : IdentityUser<long>
{
    public Role Role { get; set; }
    public long? RoleId { get; set; }
}