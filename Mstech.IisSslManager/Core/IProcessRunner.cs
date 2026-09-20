using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Core;

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        ProcessRequest request,
        CancellationToken cancellationToken = default);
}
