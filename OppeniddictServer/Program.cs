using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OppeniddictServer.ClientManager;
using OppeniddictServer.Interface;
using OppeniddictServer;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddRazorPages();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});


// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<AppDbContext>();
    })
    .AddServer(options =>
    {        
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetLogoutEndpointUris("/connect/logout")
               .SetTokenEndpointUris("/connect/token");

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .SetAccessTokenLifetime(TimeSpan.FromMinutes(1))
               .SetRefreshTokenLifetime(TimeSpan.FromMinutes(30));

        options.AddEncryptionKey(new SymmetricSecurityKey(
           Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableLogoutEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()               
               .EnableTokenEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// Configure cookie authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(c =>
                {
                    c.LoginPath = "/Authenticate";
                });

builder.Services.AddTransient<AuthService>();
builder.Services.AddTransient<ClientSeeder>();
builder.Services.AddScoped<IClientService, ClientService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder => builder
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientSeeder>();
    seeder.AddClients().GetAwaiter().GetResult();
    seeder.AddScopes().GetAwaiter().GetResult();
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("?Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseCors("AllowAllOrigins");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

app.Run();
