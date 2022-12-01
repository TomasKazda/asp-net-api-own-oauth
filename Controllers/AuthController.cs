using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using aspnetapireactoauth.Services;

namespace aspnetapireactoauth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _as;

        public AuthController(AuthService auths)
        {
            this._as = auths;
        }

        [HttpGet("login")]
        public IActionResult Authenticate(string username, string password)
        {
            var token = _as.Authentication(new Models.User
            {
                UserName = username,
                Password = password
            });
            if (token == null)
            {
                return Unauthorized();
            }
            return Ok(token);
        }
    }
}
