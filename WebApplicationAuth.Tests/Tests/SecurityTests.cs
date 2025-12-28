using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using WebApplicationAuth.Controllers;
using Xunit;

namespace WebApplicationAuth.Tests
{
    public class AccountControllerTests
    {
        private static AccountController CreateController()
        {
            // Construir UserManager mock mínimo
            var configuration = new Mock<IConfiguration>().Object;
            var userStoreMock = new Mock<IUserStore<IdentityUser>>().Object;
            var userManagerMock = new Mock<UserManager<IdentityUser>>(
                userStoreMock,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null).Object;

            // Construir SignInManager mock mínimo
            var signInManagerMock = new Mock<SignInManager<IdentityUser>>(
                userManagerMock,
                Mock.Of<Microsoft.AspNetCore.Http.IHttpContextAccessor>(),
                Mock.Of<IUserClaimsPrincipalFactory<IdentityUser>>(),
                Options.Create(new IdentityOptions()),
                NullLogger<SignInManager<IdentityUser>>.Instance,
                Mock.Of<IAuthenticationSchemeProvider>(),
                Mock.Of<IUserConfirmation<IdentityUser>>()).Object;

            return new AccountController(userManagerMock, signInManagerMock, configuration);
        }

        [Fact]
        public void LoginSecure_ValidUser_ReturnsOkWithSuccessTrue()
        {
            var controller = CreateController();

            var result = controller.LoginSecure("test@example.com", "Password123!");

            var ok = Assert.IsType<OkObjectResult>(result);
            var successProp = ok.Value?.GetType().GetProperty("success");
            Assert.NotNull(successProp);
            Assert.True((bool)successProp.GetValue(ok.Value)!);
        }

        [Fact]
        public void LoginSecure_SQLInjectionAttempt_ReturnsBadRequestOrFalse()
        {
            var controller = CreateController();

            // Intento típico de SQLi
            var maliciousUser = "'; DROP TABLE Users; --";
            var maliciousPassword = "anything";

            var result = controller.LoginSecure(maliciousUser, maliciousPassword);

            // El controlador hace saneamiento; si queda vacío devuelve BadRequest({ success = false })
            if (result is BadRequestObjectResult bad)
            {
                var successProp = bad.Value?.GetType().GetProperty("success");
                Assert.NotNull(successProp);
                Assert.False((bool)successProp.GetValue(bad.Value)!);
            }
            else if (result is OkObjectResult ok)
            {
                // En caso de devolver Ok, verificar que success == false
                var successProp = ok.Value?.GetType().GetProperty("success");
                Assert.NotNull(successProp);
                Assert.False((bool)successProp.GetValue(ok.Value)!);
            }
            else
            {
                Assert.True(false, $"Resultado inesperado: {result.GetType().FullName}");
            }
        }

        [Fact]
        public void LoginSecure_XSSAttempt_ReturnsBadRequestOrFalse()
        {
            var controller = CreateController();

            // Intento típico de XSS
            var maliciousUser = "<script>alert('xss')</script>";
            var maliciousPassword = "<script>mal</script>";

            var result = controller.LoginSecure(maliciousUser, maliciousPassword);

            // Igual que en SQLi: el método debe sanear y no permitir que el input siga como válido.
            if (result is BadRequestObjectResult bad)
            {
                var successProp = bad.Value?.GetType().GetProperty("success");
                Assert.NotNull(successProp);
                Assert.False((bool)successProp.GetValue(bad.Value)!);
            }
            else if (result is OkObjectResult ok)
            {
                var successProp = ok.Value?.GetType().GetProperty("success");
                Assert.NotNull(successProp);
                Assert.False((bool)successProp.GetValue(ok.Value)!);
            }
            else
            {
                Assert.True(false, $"Resultado inesperado: {result.GetType().FullName}");
            }
        }
    }
}