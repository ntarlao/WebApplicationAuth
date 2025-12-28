using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using System.Data;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApplicationAuth.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        // Conexión a base de datos SQLite en memoria compartida por la aplicación
        private static readonly SqliteConnection _inMemoryConnection;

        static AccountController()
        {
            // Cadena de conexión para una DB SQLite en memoria que persiste mientras haya al menos una conexión abierta.
            _inMemoryConnection = new SqliteConnection("Data Source=file:InMemoryUserAuthApp?mode=memory&cache=shared");
            _inMemoryConnection.Open();

            // Crear tabla Users y sembrar un usuario de ejemplo usando sentencias parametrizadas.
            using var cmdCreate = _inMemoryConnection.CreateCommand();
            cmdCreate.CommandText =
                @"CREATE TABLE IF NOT EXISTS Users (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    UserName TEXT NOT NULL UNIQUE,
                    Password TEXT NOT NULL
                );";
            cmdCreate.ExecuteNonQuery();

            using var cmdInsert = _inMemoryConnection.CreateCommand();
            cmdInsert.CommandText = "INSERT OR IGNORE INTO Users (UserName, Password) VALUES (@u, @p);";
            cmdInsert.Parameters.AddWithValue("@u", "test@example.com");
            cmdInsert.Parameters.AddWithValue("@p", "Password123!"); // En producción: almacenar hash
            cmdInsert.ExecuteNonQuery();
        }

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                ModelState.AddModelError("", "Invalid login attempt.");
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new IdentityUser { UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("Login");
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return View(model);
        }
        // Nuevo endpoint: eliminar usuario por id — solo accesible para rol "Admin".
        [HttpDelete]
        [Authorize(Roles = "Admin")]
        [Route("account/users/{id}")]
        public async Task<IActionResult> DeleteUser([FromRoute] string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                return BadRequest(new { success = false, error = "Invalid user id." });
            }

            // Buscar usuario por Id usando UserManager (Identity)
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new { success = false, error = "User not found." });
            }

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                var errors = result.Errors?.Select(e => e.Description) ?? Enumerable.Empty<string>();
                return StatusCode(StatusCodes.Status500InternalServerError, new { success = false, errors });
            }

            return Ok(new { success = true });
        }
        // Método solicitado: recibe usuario y contraseña, valida y sanitiza, consulta DB en memoria con parámetros.
        [HttpPost]
        [Route("account/login-secure")]
        public IActionResult LoginSecure([FromForm] string user, [FromForm] string password)
        {
            // Validación y saneamiento de entrada
            var sanitizedUser = ValidateAndSanitize(user);
            var sanitizedPassword = ValidateAndSanitize(password);

            if (string.IsNullOrWhiteSpace(sanitizedUser) || string.IsNullOrWhiteSpace(sanitizedPassword))
            {
                // Entrada inválida o potencialmente maliciosa
                return BadRequest(new { success = false });
            }

            // Consulta segura usando marcadores de posición (parámetros)
            using var cmd = _inMemoryConnection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(1) FROM Users WHERE UserName = @user AND Password = @pwd;";
            cmd.Parameters.AddWithValue("@user", sanitizedUser);
            cmd.Parameters.AddWithValue("@pwd", sanitizedPassword);

            var count = Convert.ToInt32(cmd.ExecuteScalar() ?? 0);

            if (count > 0)
            {
                // Usuario existe
                return Ok(new { success = true });
            }

            // No existe
            return Ok(new { success = false });
        }

        // Genera un token JWT para el usuario autenticado.
        private string GenerateJwtToken(IdentityUser user)
        {
            // Configuración de la clave y parámetros del token
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SigningKey"]));
            var signinCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            var tokenOptions = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:ValidAudiences"],
                claims: new[] { new Claim(ClaimTypes.NameIdentifier, user.Id) },
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:TokenExpiryMinutes"])),
                signingCredentials: signinCredentials
            );

            // Devolver token generado
            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }

        // Elimina etiquetas de script, codifica HTML y descarta patrones SQL peligrosos.
        private static string? ValidateAndSanitize(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return null;
            }

            // Limitar longitud para evitar abusos
            const int maxLen = 256;
            if (input.Length > maxLen)
            {
                return null;
            }

            // Eliminar etiquetas <script>...</script> (case-insensitive)
            var withoutScripts = Regex.Replace(input, @"(?is)<script.*?>.*?</script>", string.Empty);

            // Codificar HTML para prevenir XSS
            var encoded = WebUtility.HtmlEncode(withoutScripts);

            // Eliminar patrones comunes de inyección SQL y caracteres de control
            // Nota: la consulta usa parámetros, por lo que la inyección está mitigada; esto es defensa en profundidad.
            var cleaned = Regex.Replace(encoded, @"(--|\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|EXECUTE)\b|/\*|\*/|;)", string.Empty, RegexOptions.IgnoreCase);

            // Eliminar caracteres de control
            cleaned = Regex.Replace(cleaned, @"[\x00-\x1F\x7F]", string.Empty);

            // Resultado final
            cleaned = cleaned.Trim();

            return string.IsNullOrEmpty(cleaned) ? null : cleaned;
        }
    }
}