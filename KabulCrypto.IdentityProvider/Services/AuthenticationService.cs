using Grpc.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace KabulCrypto.IdentityProvider.GrpcService.Services;

public class AuthenticationService : Authentication.AuthenticationBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public AuthenticationService(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration
    )
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    public async override Task<AuthenticateResponse> Authenticate(AuthenticateRequest request, ServerCallContext context)
    {
        var user = await _userManager.FindByNameAsync(request.Username);

        if (user == null)
            return new AuthenticateResponse { IsAutheticated = false, ErrorMessage = "User Not Found!" };

        if (!(await _userManager.CheckPasswordAsync(user, request.Password)))
            return new AuthenticateResponse { IsAutheticated = false, ErrorMessage = "Invalid Credentials!" };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        (await _userManager.GetRolesAsync(user))
            .ToList().ForEach(role => claims.Add(new Claim(ClaimTypes.Role, role)));

        var refreshToken = GenerateToken(claims, true);

        var accessToken = GenerateToken(claims, false);

        return new AuthenticateResponse
        {
            IsAutheticated = true,
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    public async override Task<RegisterUserResponse> RegisterUser(RegisterUserRequeset request, ServerCallContext context)
    {
        var user = await _userManager.FindByNameAsync(request.Username);

        if (user != null)
            return new RegisterUserResponse { IsRegistered = false, Message = "User Already Registered" };

        user = new IdentityUser
        {
            UserName = request.Username,
            Email = request.Email,
            SecurityStamp = new Guid().ToString()
        };

        var result = await _userManager.CreateAsync(user);

        return new RegisterUserResponse { 
            IsRegistered = result.Succeeded, 
            Message = result.Succeeded ? "User Created" : "Could Not Register New User" 
        };
    }

    private string GenerateToken (List<Claim> claims, bool isRefresh)
    {
        var secretKey = _configuration["JWT:Secret"];

        var issuer = _configuration["JWT:ValidIssuer"];

        var audience = _configuration["JWT:ValidAudience"];

        var expiresAccess = int.Parse(_configuration["JWT:AccessTokenExpireHour"]!);

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!));

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: null,
            expires: DateTime.Now.AddHours(expiresAccess),
            signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
