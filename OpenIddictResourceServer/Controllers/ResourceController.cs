using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OpenIddictResourceServer.Controllers
{
    [ApiController]
    [Route("resource")]
    public class ResourceController : ControllerBase
    {
        [HttpGet("GetWithPolicy")]
        [Authorize(Policy = "RequireAdminRole")]
        public IActionResult GetWithPolicy()
        {
            var user = HttpContext.User.Identity!.Name;

            return Ok($"user: {user}");
        }

        [HttpGet("GetWithRole")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetWithRole()
        {
            var user = HttpContext.User.Identity!.Name;

            return Ok($"user: {user}");
        }

        [HttpGet]
        public IActionResult Get()
        {
            var user = HttpContext.User.Identity!.Name;

            return Ok($"user: {user}");
        }
    }
}
