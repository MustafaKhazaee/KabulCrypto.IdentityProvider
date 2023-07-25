

namespace KabulCrypto.IdentityProvider
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.RegisterServices(builder.Configuration);

            var app = builder.Build();

            app.UseAuthentication();

            app.UseAuthorization();

            // Map GRPC Service After Auth 
            //app.MapGrpcService<GreeterService>();

            app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");

            app.Run();
        }
    }
}