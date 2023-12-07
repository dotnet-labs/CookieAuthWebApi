using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MyWebApp.Controllers;

[Route("[controller]")]
[ApiController, Produces("application/json")]
public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
{
    [HttpPost("Register")]
    public async Task<ActionResult> Register([FromBody] UserRegistrationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var identityUser = new IdentityUser { UserName = request.UserName, Email = request.Email };
        var result = await userManager.CreateAsync(identityUser, request.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(error.Code, error.Description);
            }

            return BadRequest(ModelState);
        }

        return Ok();
    }

    [HttpPost("Login")]
    public async Task<IActionResult> Login([FromBody] LoginCredentials credentials)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var identityUser = await userManager.FindByNameAsync(credentials.UserName);
        if (identityUser == null)
        {
            return BadRequest(ModelState);
        }

        var result = userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash ?? string.Empty, credentials.Password);
        if (result == PasswordVerificationResult.Failed)
        {
            return BadRequest(ModelState);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, identityUser.Email?? string.Empty),
            new(ClaimTypes.Name, identityUser.UserName?? string.Empty)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

        return Ok();
    }

    [HttpPost("Logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok();
    }
}

public class UserRegistrationRequest
{
    [Required] public string UserName { get; set; } = string.Empty;
    [Required] public string Password { get; set; } = string.Empty;
    [Required] public string Email { get; set; } = string.Empty;
}

public class LoginCredentials
{
    [Required] public string UserName { get; set; } = string.Empty;
    [Required] public string Password { get; set; } = string.Empty;
}