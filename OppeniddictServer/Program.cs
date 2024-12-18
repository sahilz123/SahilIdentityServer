using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OppeniddictServer.ClientManager;
using OppeniddictServer;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OppeniddictServer.Context;
using Microsoft.AspNetCore.Identity;
using OppeniddictServer.Identity;
using OppeniddictServer.Openiddict;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddRazorPages();

builder.Services.AddDbContext<AdminIdentityDbContext>(options =>
{
    
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddDbContext<OpenIddictDbContext>(options =>
{
    options.UseOpenIddict();
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<UserIdentity, UserIdentityRole>(options =>
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
       .AddDefaultTokenProviders()
       .AddSignInManager();

//builder.Services.AddDefaultIdentity<UserIdentity>(o=>o);

// Configure OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<OpenIddictDbContext>();

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
                    c.LoginPath = "/ServerLogin";
                });

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = ".AspNetCore.Identity.Application";
    options.LoginPath = "/ServerLogin"; // Redirect path for login
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.AccessDeniedPath = "/Error"; 
});

builder.Services.AddTransient<AuthService>();
builder.Services.AddScoped<ClientSeeder>();
builder.Services.AddScoped<ScopesManager>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        builder => builder
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader());
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminPolicy", policy =>
        policy.RequireRole("SuperAdmin"));
});



var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientSeeder>();
    //seeder.AddClients().GetAwaiter().GetResult();
    //seeder.AddScopes().GetAwaiter().GetResult();
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
