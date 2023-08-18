using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(s=>
    {
        var logger = new LoggerConfiguration()
            .WriteTo.Console()
            .CreateLogger();
        s.AddLogging(b => b.AddSerilog(logger, true));
    })
    .Build();

host.Run();