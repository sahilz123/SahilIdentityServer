using Microsoft.AspNetCore.Identity;
using OppeniddictServer.Identity;
using System.Net;
namespace OppeniddictServer
{
    public class ExceptionFilter 
    {
       private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionFilter> _logger;
        private readonly IServiceScopeFactory _scopeFactory;


        public ExceptionFilter( RequestDelegate next, ILogger<ExceptionFilter> logger, IServiceScopeFactory scopeFactory)
        {
            _next = next;
            _logger = logger;
            _scopeFactory = scopeFactory;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch(Exception ex)
            {
                if (context.User.Identity?.IsAuthenticated == true)
                {
                    using (var scope = _scopeFactory.CreateScope())
                    {
                        var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<UserIdentity>>();
                        await signInManager.SignOutAsync();
                        _logger.LogInformation("User has been logged out due to an exception.");
                    }
                }
                    await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            _logger.LogError(exception, "An unexpected error occurred.");

            //More log stuff        

            ExceptionResponse response = exception switch
            {
                ApplicationException _ => new ExceptionResponse(HttpStatusCode.BadRequest, "Application exception occurred."),
                KeyNotFoundException _ => new ExceptionResponse(HttpStatusCode.NotFound, "The request key not found."),
                UnauthorizedAccessException _ => new ExceptionResponse(HttpStatusCode.Unauthorized, "Unauthorized."),
                _ => new ExceptionResponse(HttpStatusCode.InternalServerError, "Internal server error. Please retry later.")
            };

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)response.StatusCode;
            await context.Response.WriteAsJsonAsync(response);
        }
    }

    internal class ExceptionResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public string StatusMessage { get; set; } = string.Empty;

        public ExceptionResponse(HttpStatusCode statusCodes,string message)
        {
            StatusCode = statusCodes;
                StatusMessage = message;
        }
    }
}
