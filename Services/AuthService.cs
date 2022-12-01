using aspnetapireactoauth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace aspnetapireactoauth.Services
{

    public class AuthService
    {
        private readonly IConfiguration _configuration;

        public AuthService(IConfiguration conf)
        {
            this._configuration = conf;
        }

        public AuthenticationToken Authentication(User u)
        {
            //if u.Password == db.Password && u.UserName == db.UserName

            //return CreateAuthenticationToken(u);
            //else
            u.UserId = 123;
            return CreateAuthenticationToken(u);
            //return null;
        }

        private AuthenticationToken CreateAuthenticationToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            int validityDuration;
            int.TryParse(_configuration["JWT:Expiration"], out validityDuration);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new(ClaimTypes.Name, user.UserName),
                    new(ClaimTypes.NameIdentifier, user.UserId.ToString())
                }),
                Issuer = _configuration["JWT:Issuer"],
                Audience = _configuration["JWT:Audience"],
                Expires = DateTime.UtcNow.AddMinutes(validityDuration),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return new AuthenticationToken()
            {
                 Value = tokenHandler.WriteToken(token),
            };
        }
    }
}
