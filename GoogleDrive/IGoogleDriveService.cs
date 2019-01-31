using System;
using System.Collections.Generic;
using System.IO;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace DSide.GoogleDrive
{
    public interface IGoogleDriveService
    {
        Task<IGoogleDriveFile> GetFileAsync(string fileId);
        Task<IGoogleDriveFile[]> GetFilesAsync(IEnumerable<string> fileIds);
        Task DeleteFileAsync(string fileId);
        Task<IGoogleDriveFile[]> GetFilesAsync(Expression<Func<GoogleDriveFileListQuery, bool>> query);
        Task DeleteFilesAsync(IEnumerable<string> fileIds);
        Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data);
        Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data, string description);
        Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data, object properties);
        Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data, string description, object properties);
        Task MoveFileAsync(string fileId, string destId);
        Task MoveFilesAsync(IEnumerable<string> fileIds, string destId);
        Task<(long Limit, long Usage, long UsageInDrive, long UsageInDriveTrash)> GetStorageQuota();
    }
}