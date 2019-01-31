using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace DSide.GoogleDrive
{
    public interface IGoogleDriveFile 
    {
        string Id { get; }
        bool Exists { get; }
        long Length { get; }
        string ContentUrl { get; }
        string Name { get; }
        DateTime LastModified { get; }
        DateTime Created { get; }
        bool IsDirectory { get; }
        string MimeType { get;}
        string Descrption { get; }
        IDictionary<string, string> Properties { get; }
        bool HasPreview { get; }
        string PreviewUrl { get; }

        Task<Stream> GetContentStreamAsync();
        Task<Stream> GetContentPreviewStreamAsync();
    }
}
