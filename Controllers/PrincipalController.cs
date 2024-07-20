using System.Diagnostics;
using System.Security.Principal;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using pruebaMega.Models;

namespace pruebaMega.Controllers;

[Authorize]
public class PrincipalController : Controller
{

    private readonly IDataProtector _protector;

    public PrincipalController(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("JWTTokenProtector");
    }
    public IActionResult Index()
    {

        var encryptedToken = Request.Cookies["AuthToken"];
        var encryptedid = Request.Cookies["perfil"];
        var encryptedusuario = Request.Cookies["usuario"];
        string token = "";
        string perfil = "";
        string usuario = "";
        if (encryptedusuario != null)
        {

            usuario = _protector.Unprotect(encryptedusuario);


        }
        if (encryptedid != null)
        {

            perfil = _protector.Unprotect(encryptedid);


        }
        if (encryptedToken != null)
        {

            token = _protector.Unprotect(encryptedToken);


        }
        ViewBag.token = token;
        ViewBag.perfil = perfil;
        ViewBag.usuario = usuario;
        return View();
    }



}
