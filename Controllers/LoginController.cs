using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using pruebaMega.Models;

namespace pruebaMega.Controllers;

[AllowAnonymous]
public class LoginController : Controller
{

    private readonly HttpClient _httpClient;
    private readonly IDataProtector _protector;
    public LoginController(HttpClient httpClient, IDataProtectionProvider provider)
    {
        _httpClient = httpClient;
        _protector = provider.CreateProtector("JWTTokenProtector");
    }




    public IActionResult Index()
    {
        return View();
    }

    public IActionResult denegado()
    {

        return View("no autorizado");
    }

    [HttpPost]
    public async Task<IActionResult> ingresarAsync(string email, string password)
    {

        var loginRequest = new
        {
            email = email,
            password = password
        };

        var response = await _httpClient.PostAsJsonAsync("http://localhost:8080/login/ingresar", loginRequest);

        if (response.IsSuccessStatusCode)
        {
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, loginRequest.email)
                };

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                new AuthenticationProperties
                {
                    IsPersistent = true
                });
            var loginResponse = await response.Content.ReadFromJsonAsync<LoginResponse>();
            SetTokenCookie(loginResponse.Token, loginResponse.id, email);
            return RedirectToAction("index", "principal");


        }
        else
        {
            return Unauthorized("Usuario invalido");
        }

    }

    private class LoginResponse
    {
        public string Token { get; set; }
        public int id { get; set; }
    }

    private void SetTokenCookie(string token, int id, string email)
    {
        var encryptedToken = _protector.Protect(token);
        var encryptedid = _protector.Protect(id.ToString());
        var encryptedemail = _protector.Protect(email);
        var cookieOptions = new CookieOptions
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };

        Response.Cookies.Append("perfil", encryptedid, cookieOptions);
        Response.Cookies.Append("AuthToken", encryptedToken, cookieOptions);
        Response.Cookies.Append("usuario", encryptedemail, cookieOptions);

    }

}
