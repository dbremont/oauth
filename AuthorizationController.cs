using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using dontis.gateway.Models.v1;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Annotations;

namespace dontis.gateway.Controllers;

public class AuthorizationController : ControllerBase
{
    private static Dictionary<string, string> tokenDatabase = new Dictionary<string, string>();
    private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

    public AuthorizationController()
    {
        _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
    }

    [HttpGet("/login")]
    [SwaggerOperation(Summary = "Login")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    public IResult Login()
    {
        // return Results.Challenge(
        //     new AuthenticationProperties()
        //     {
        //         RedirectUri = "https://localhost:5002/swagger/index.html"
        //     },
        //     authenticationSchemes: new List<string>() { "custom" }
        // );
    }

    [HttpGet("/oauth2/authorize")]
    [SwaggerOperation(Summary = "Authorize")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    public IActionResult Authorize()
    {
        string state = Request.Query.ContainsKey("state") ? Request.Query["state"].ToString() : Guid.NewGuid().ToString("N");
        string code = Guid.NewGuid().ToString("N");
        string redirectUri = Request.Query["redirect_uri"];
        string responseType = Request.Query["response_type"];
        string clientId = Request.Query["client_id"];

        Console.WriteLine("----------------------");
        Console.WriteLine("I Enter Here Authorize");
        Console.WriteLine(code);
        Console.WriteLine(responseType);
        Console.WriteLine(clientId);
        Console.WriteLine(redirectUri);
        Console.WriteLine("----------------------");

        if (responseType == "code")
        {
            tokenDatabase[code] = clientId;
            try
            {
                return Redirect($"{redirectUri}?state={state}&code={code}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error");
                throw new Exception("Error");
            }
        }

        return BadRequest("Invalid response type.");
    }

    [HttpPost("/oauth2/token")]
    [SwaggerOperation(Summary = "Token")]
    [ProducesResponseType(typeof(Token), StatusCodes.Status200OK)]
    public IActionResult Token()
    {
        Console.WriteLine("I Enter Here Token");

        string code = Request.Form["code"];
        string clientId = Request.Form["client_id"];
        string clientSecret = Request.Form["client_secret"];

        Console.WriteLine("--------------------");
        Console.WriteLine(code);
        Console.WriteLine(clientId);
        Console.WriteLine(tokenDatabase.GetValueOrDefault(code, null));
        Console.WriteLine("--------------------");

        if (tokenDatabase.TryGetValue(code, out var storedClientId) && clientId == storedClientId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("ju0Lf7DVniA51ZMp4I92wplAksisG1cfKPdhhgpD5P0");

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "user123"),
                    new Claim("name", "John Doe"),
                    new Claim("email", "john.doe@example.com"),
                    new Claim("iss", "https://auth.example.com"),
                    new Claim("aud", "api.example.com"),
                    new Claim("scope", "read write"),
                    new Claim(ClaimTypes.Role, "weather:read"),
                    new Claim(ClaimTypes.Role, "admin")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var accessToken = tokenHandler.WriteToken(token);

            tokenDatabase.Remove(code);

            Console.WriteLine("Token: " + accessToken);

            return Ok(new Token
            {
                access_token = accessToken,
                token_type = "bearer"
            });
        }
        return BadRequest(new { error = "invalid_grant" });
    }

    [HttpGet("/oauth2/userinfo")]
    [SwaggerOperation(Summary = "Userinfo")]
    public IActionResult UserInfo()
    {
        return Ok();
    }

    [HttpGet("oauth2/revoke")]
    [SwaggerOperation(Summary = "Revoke")]
    public IActionResult Revoke()
    {
        HttpContext.SignOutAsync();
        return Ok();
    }

    [HttpPost("/.well-known/openid-configuration")]
    [SwaggerOperation(Summary = "Configuration")]
    public IActionResult Configuration()
    {
        return Ok();
    }
}
