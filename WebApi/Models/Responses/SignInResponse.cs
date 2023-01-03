using System.Text.Json.Serialization;

namespace WebApi.Models.Responses
{
    public class SignInResponse
    {
        [JsonPropertyName("access_token")] public string AccessToken { get; init; } = string.Empty;

        [JsonPropertyName("refresh_token")] public string RefreshToken { get; init; } = string.Empty;
        [JsonPropertyName("user_id")] public long UserId { get; init; }
    }
}