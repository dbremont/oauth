using System.IdentityModel.Tokens.Jwt;
using System.Text;
using dontis.gateway.Controllers;
using dontis.gateway.Helpers;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.SwaggerUI;

namespace dontis.gateway
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            
            services.AddTransient<ProblemDetailsFactory, CustomProblemDetailsFactory>();

            // Development Mode
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.EnableAnnotations();
                c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
                {
                    Version = "v1",
                    Title = "Dontis API Gateway",
                    Description = ".Net Core API"
                });

            });

            // Configuration
            services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = 100_000_000; // Set the maximum file size (in bytes)
            });

            // services
            // .AddAuthentication("cookie")
            // .AddCookie("cookie")
            // .AddOAuth("custom", o =>
            // {
            //     o.SignInScheme = "cookie";
            //     o.ClientId = "x";
            //     o.AuthorizationEndpoint = "https://localhost:5002/oauth/authorize";
            //     o.TokenEndpoint = "https://localhost:5002/oauth/token";
            //     o.UsePkce = true;
            //     o.CallbackPath = "/oauth/signin";
            //     o.ClientSecret = "1212";
            //     o.BackchannelHttpHandler = new HttpClientHandler
            //     {
            //         ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            //     };
            //     o.Events.OnCreatingTicket = async ctx =>
            //     {
            //         Console.WriteLine("Token " + ctx.AccessToken);

            //         var tokenHandler = new JwtSecurityTokenHandler();
            //         var jwtToken = ctx.AccessToken;
            //         var secretKey = "ju0Lf7DVniA51ZMp4I92wplAksisG1cfKPdhhgpD5P0";
            //         Console.WriteLine(jwtToken);

            //         // Configure validation parameters (optional)
            //         var validationParameters = new TokenValidationParameters
            //         {
            //             ValidateIssuerSigningKey = true,
            //             ValidateLifetime = false,
            //             IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),
            //             ValidateIssuer = false, // You can set this to true if needed
            //             ValidateAudience = false, // You can set this to true if needed
            //             ClockSkew = TimeSpan.Zero // Optional: Set the clock skew tolerance
            //         };

            //         var claimsPrincipal = tokenHandler.ValidateToken(jwtToken, validationParameters, out var validatedToken);
            //         ctx.Principal = claimsPrincipal;

            //         ctx.RunClaimActions();
            //     };
            // });

            services.AddHttpClient();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Configure the HTTP request pipeline.
            if (env.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI(options =>
                {
                    options.DocExpansion(DocExpansion.None);
                });
            }

            app.UseRouting();
            app.UseEndpoints(endpoints =>
             {
                 endpoints.MapControllers(); // This maps all controllers to their routes.
             });

            app.UseHttpsRedirection();
            // app.UseAuthentication();
            app.UseAuthorization();
        }
    }
}
