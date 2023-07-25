
using KabulCrypto.IdentityProvider.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace KabulCrypto.IdentityProvider.Infrastructure;

public static class DependencyInjection
{
    public static void AddInfrastructure (this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseNpgsql(connectionString);
                options.EnableDetailedErrors();
            },
            ServiceLifetime.Scoped
        );
    }
}
