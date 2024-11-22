using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OppeniddictServer.ClientManager;
using OppeniddictServer;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OppeniddictServer.Context;
using Microsoft.AspNetCore.Identity;
using OppeniddictServer.Identity;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddRazorPages();

builder.Services.AddDbContext<AdminIdentityDbContext>(options =>
{
    
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

builder.Services.AddIdentity<UserIdentity, UserIdentityRole>(options=>
{
    // Password settings
    options.Password.RequireDigit = true; 
    options.Password.RequiredLength = 8; 
    options.Password.RequireNonAlphanumeric = true; 
    options.Password.RequireUppercase = true; 
    options.Password.RequireLowercase = true; 
    options.Password.RequiredUniqueChars = 3; 

    // User settings
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true; 
   
}

    )
       .AddEntityFrameworkStores<AdminIdentityDbContext>()
       .AddDefaultTokenProviders();

// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               //.UseDbContext<AppDbContext>();
               .UseDbContext<AdminIdentityDbContext>();

    })
    .AddServer(options =>
    {        
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetLogoutEndpointUris("/connect/logout")
               .SetTokenEndpointUris("/connect/token");

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .SetAccessTokenLifetime(TimeSpan.FromMinutes(5))
               .SetRefreshTokenLifetime(TimeSpan.FromMinutes(30));

        options.AddEncryptionKey(new SymmetricSecurityKey(
           Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableLogoutEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()               
               .EnableTokenEndpointPassthrough();
        options.DisableAccessTokenEncryption();
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
//builder.Services.AddScoped<IClientService, ClientService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder => builder
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});

var app = builder.Build();

//using (var scope = app.Services.CreateScope())
//{
//    var seeder = scope.ServiceProvider.GetRequiredService<ClientSeeder>();
//    seeder.AddClients().GetAwaiter().GetResult();
//    seeder.AddScopes().GetAwaiter().GetResult();
//}

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var roleManager = services.GetRequiredService<RoleManager<UserIdentityRole>>();

    // Seed the roles if they do not exist
    await SeedRoles.Initialize(services, roleManager);
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
