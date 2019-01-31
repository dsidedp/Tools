using System;
using System.Reflection;
using Google.Apis.Auth.OAuth2;

namespace DSide.GoogleDrive
{
    public class GoogleDriveOptions
    {
        public JsonCredentialParameters CredentialParameters { get; set; }
        public string ApplicationName { get; set; } = Assembly.GetEntryAssembly().GetName().Name;
        public TimeSpan TimeOut { get; set; } = TimeSpan.FromMinutes(1);
        public bool SupportsTeamDrives { get; set; }
        public string StorageRoot { get; set; } = "root";
        public string RootFolderName { get; set; }
        public string ShareWithAccount { get; set; }
        public int ParallelRequests { get; set; } = 5;
    }
}
