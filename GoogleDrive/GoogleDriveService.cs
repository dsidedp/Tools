using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Google;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Download;
using Google.Apis.Drive.v3;
using Google.Apis.Drive.v3.Data;
using Google.Apis.Http;
using Google.Apis.Requests;
using Google.Apis.Services;
using Google.Apis.Util;
using Google.Apis.Util.Store;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using File = Google.Apis.Drive.v3.Data.File;

//todo: exclusive file name mode
//todo: folder strategy
//todo: extensions
//todo: search scopes
namespace DSide.GoogleDrive
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public class GoogleDriveService : IGoogleDriveService
    {
        public const string ContentTypePropertyName = "ContentType";
        private const string GoogleDriveFolderMime = "application/vnd.google-apps.folder";
        private const string GoogleDriveFileFieldList = "createdTime,modifiedTime,description,id,mimeType,name,properties,size,webContentLink, hasThumbnail,thumbnailLink";

        private readonly DriveService _driveService;
        private readonly GoogleDriveOptions _config;
        private readonly ILogger<GoogleDriveService> _logger;

        private Lazy<Task<string>> RootId => Roots.GetOrAdd(_config, new Lazy<Task<string>>(async () => await GetOrCreateRootFolderIdAsync().ConfigureAwait(false)));
        private static readonly ConcurrentDictionary<object, Lazy<Task<string>>> Roots = new ConcurrentDictionary<object, Lazy<Task<string>>>();

        private static string QuotaUser => Guid.NewGuid().ToString("N");

        public GoogleDriveService(IOptions<GoogleDriveOptions> config, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<GoogleDriveService>();
            _config = config?.Value ?? throw new ArgumentNullException(nameof(config));

            var httpInitializer = ValidateAndGetInitializer(_config);

            var svcInit = new BaseClientService.Initializer()
            {
                HttpClientInitializer = httpInitializer(),
                ApplicationName = _config.ApplicationName,
                DefaultExponentialBackOffPolicy = ExponentialBackOffPolicy.None
            };
            _driveService = new DriveService(svcInit) {HttpClient =
            {
                Timeout = _config.TimeOut,
                MessageHandler = { NumTries = 20}
            }};

            var retryStatusCodes = new[] {HttpStatusCode.InternalServerError, HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable};

            var backoffHandler = new BackOffHandler(new BackOffHandler.Initializer(new ExponentialBackOff(TimeSpan.FromMilliseconds(500), 20))
            {
                MaxTimeSpan = TimeSpan.FromSeconds(65),
                HandleExceptionFunc = exception =>
                {
                    var willDoBackoff = BackOffHandler.Initializer.DefaultHandleExceptionFunc(exception);
                    _logger.LogInformation($"'Exception' request: {exception.Message}. Try backoff: {willDoBackoff}");
                    return willDoBackoff;
                },
                HandleUnsuccessfulResponseFunc = response =>
                {
                    var msg = $"'Unsuccessful' request: {response.StatusCode}. ";
                    var willDoBackoff = retryStatusCodes.Contains(response.StatusCode);

                    if (!willDoBackoff)
                    {
                        try
                        {
                            var e = _driveService.DeserializeError(response).Result;
                            msg += $"Reason: {(e.Errors?.Any() == true ? e.Errors[0].Reason : "unknown")}";

                            willDoBackoff = response.StatusCode == HttpStatusCode.Forbidden && (e.Errors[0].Reason == "rateLimitExceeded" || e.Errors[0].Reason == "userRateLimitExceeded");
                        }
                        catch
                        {
                        }
                    };
                    _logger.LogInformation($"{msg} Backoff: {willDoBackoff}");
                    return willDoBackoff;
                }
            });
            _driveService.HttpClient.MessageHandler.AddUnsuccessfulResponseHandler(backoffHandler);
            _driveService.HttpClient.MessageHandler.AddExceptionHandler(backoffHandler);
        }

        #region service init
        private Func<IConfigurableHttpClientInitializer> ValidateAndGetInitializer(GoogleDriveOptions config)
        {
            if (_config.CredentialParameters == null) throw new ArgumentNullException(nameof(_config.CredentialParameters));

            //config should have either svc account config(ClientEmail, PrivateKey) or user account config(ClientId, ClientSecret, RefreshToken)
            var hasSvcAccount = !string.IsNullOrWhiteSpace(_config.CredentialParameters.ClientEmail) && !string.IsNullOrWhiteSpace(_config.CredentialParameters.PrivateKey);
            var hasUserAccount = !string.IsNullOrWhiteSpace(_config.CredentialParameters.ClientId) && !string.IsNullOrWhiteSpace(_config.CredentialParameters.ClientSecret) && !string.IsNullOrWhiteSpace(_config.CredentialParameters.RefreshToken);

            if (hasSvcAccount && hasUserAccount) throw new ArgumentException("Ambiguous account configuration. Only Service(ClientEmail, PrivateKey) or User(ClientId, ClientSecret, RefreshToken) account data should be provided.");
            if (!hasSvcAccount && !hasUserAccount) throw new ArgumentException("No valid account configuration present.");
            
            if (string.IsNullOrWhiteSpace(_config.ApplicationName)) throw new ArgumentNullException(nameof(_config.ApplicationName));
            if (string.IsNullOrWhiteSpace(_config.StorageRoot)) throw new ArgumentNullException(nameof(_config.StorageRoot));

            _config.RootFolderName = !string.IsNullOrWhiteSpace(_config.RootFolderName) ? _config.RootFolderName : _config.ApplicationName;

            if (hasSvcAccount) return ServiceAccountInitializer;
            else if (hasUserAccount) return UserAccountInitializer;
            else throw new InvalidOperationException("Invalid configuration exception");
        }

        private IConfigurableHttpClientInitializer ServiceAccountInitializer()
        {
            var svcInit = new ServiceAccountCredential.Initializer(_config.CredentialParameters.ClientEmail)
            {
                Scopes = new[] { DriveService.Scope.Drive }
            };
            return new ServiceAccountCredential(svcInit.FromPrivateKey(_config.CredentialParameters.PrivateKey));
        }

        private IConfigurableHttpClientInitializer UserAccountInitializer()
        {
            var authFlowInit = new GoogleAuthorizationCodeFlow.Initializer()
            {
                ClientSecrets = new ClientSecrets()
                {
                    ClientId = _config.CredentialParameters.ClientId,
                    ClientSecret = _config.CredentialParameters.ClientSecret
                },
                Scopes = new[] { DriveService.Scope.Drive },
                DataStore = new NullDataStore()
            };
            return new UserCredential(new GoogleAuthorizationCodeFlow(authFlowInit), "Backend User", new TokenResponse() { RefreshToken = _config.CredentialParameters.RefreshToken });
        }
        #endregion

        #region get
        public Task<IGoogleDriveFile> GetFileAsync(string fileId) => GetFilesAsync(new[] {fileId}).ContinueWith(t => t.Result.First());
        public async Task<IGoogleDriveFile[]> GetFilesAsync(IEnumerable<string> fileIds)
        {
            var files = fileIds as string[] ?? fileIds.ToArray();
            var results = await InternalGetFilesAsync(files, x => GoogleDriveFile.Create(x, this));
            results.AddRange(files.Except(results.Select(x => x.Id)).Select(GoogleDriveFile.CreateNonExisting));
            return results.Cast<IGoogleDriveFile>().ToArray();
        }

        private Task<List<T>> InternalGetFilesAsync<T>(IEnumerable<string> fileIds, Func<File, T> factory, string fields = GoogleDriveFileFieldList)
        {
            var getRequests = (fileIds ?? Enumerable.Empty<string>()).Select(x =>
                new FilesResource.GetRequest(_driveService, x)
                {
                    Fields = fields,
                    QuotaUser = QuotaUser,
                    SupportsTeamDrives = _config.SupportsTeamDrives
                });

            var result = RequestRunner<FilesResource.GetRequest, File>(getRequests, msgBuiler:request => $"Getting {request.FileId}");

            return Task.FromResult(result.Select(factory).ToList());
        }

        public async Task<IGoogleDriveFile[]> GetFilesAsync(Expression<Func<GoogleDriveFileListQuery, bool>> query)
        {
            try
            {
                var q = GoogleDriveFileListQuery.Parse(query);
                //todo: rework this
                if (!q.Contains("in parents")) q = $"({q}) and ({GoogleDriveFileListQuery.Parse(x => x.Parents.Contains(RootId.Value.Result))})";
                _logger.LogInformation($"Searching for {q}");
                var req = new FilesResource.ListRequest(_driveService)
                {
                    Fields = $"files({GoogleDriveFileFieldList}), nextPageToken",
                    Q = q,
                    QuotaUser = QuotaUser,
                    PageSize = 1000,
                    SupportsTeamDrives = _config.SupportsTeamDrives,
                    IncludeTeamDriveItems = _config.SupportsTeamDrives
                };
                var files = await GetPageStreamer().FetchAllAsync(req, CancellationToken.None);

                return files.Select(x => GoogleDriveFile.Create(x, this)).Cast<IGoogleDriveFile>().ToArray();
            }
            catch (GoogleApiException ex)
            {
                
                if (ex.HttpStatusCode == HttpStatusCode.BadRequest)
                {
                    throw new NotSupportedException($"Translation failed for {query.Body}. ");
                }
                throw;
            }
        }
        #endregion

        #region delete
        public Task DeleteFileAsync(string fileId) => DeleteFilesAsync(new[] {fileId});

        public Task DeleteFilesAsync(IEnumerable<string> fileIds)
        {
            var removeReqs = (fileIds ?? Enumerable.Empty<string>()).Select(x =>
                new FilesResource.DeleteRequest(_driveService, x)
                {
                    QuotaUser = QuotaUser,
                    SupportsTeamDrives = _config.SupportsTeamDrives
                });

            RequestRunner<FilesResource.DeleteRequest, string>(removeReqs, msgBuiler: request => $"Deleting {request.FileId}");

            return Task.CompletedTask;
        }

        #endregion

        #region move
        public Task MoveFileAsync(string fileId, string destId) => MoveFilesAsync(new[] {fileId}, destId);

        public async Task MoveFilesAsync(IEnumerable<string> fileIds, string destId)
        {
            if (string.IsNullOrEmpty(destId)) throw new ArgumentNullException($"Destination folder cannot be null");
            var files = await InternalGetFilesAsync(fileIds, x => x, "id, parents");

            var moveReqs = files.Select(x =>
            {
                var uReq = _driveService.Files.Update(new File(), x.Id);
                uReq.AddParents = destId;
                uReq.RemoveParents = string.Join(',', x.Parents);
                uReq.SupportsTeamDrives = _config.SupportsTeamDrives;
                uReq.QuotaUser = QuotaUser;
                return uReq;
            });

            RequestRunner<FilesResource.UpdateRequest, File>(moveReqs, msgBuiler: request => $"Moving {request.FileId}");
        }

        #endregion

        #region root folder creation/sharing - should be reviewed after sometime
        private async Task<string> GetOrCreateRootFolderIdAsync()
        {
            _logger.LogInformation($"Access app root '{_config.RootFolderName}' in '{_config.StorageRoot}'");
            var isTeamDrive = false;
            var pathItems = _config.StorageRoot.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (pathItems[0].ToLower() != "root")
            {
                isTeamDrive = true;
                var tdReq = new TeamdrivesResource.ListRequest(_driveService) {Fields = "teamDrives(id,name)", QuotaUser = QuotaUser};
                var tds = await tdReq.ExecuteAsync();
                var td = tds.TeamDrives.FirstOrDefault(x => x.Name == pathItems[0]);
                if (td == null) throw new ApplicationException($"TeamDrive '{pathItems[0]}' not found");
                pathItems[0] = td.Id;
                _logger.LogInformation($"TeamDrive id: {pathItems[0]}");
            }

            //todo: add nested path parsing
            var baseRoot = pathItems[0];

            var rootFolder = await GetFilesAsync(x => x.Name == _config.RootFolderName && x.Parents.Contains(baseRoot));
            if (rootFolder.Count(x=>x.IsDirectory) > 1) throw new InvalidOperationException($"More than one {_config.RootFolderName} folders exists in the drive root.");
            var rootId = rootFolder.FirstOrDefault(x => x.IsDirectory)?.Id;

            if (!rootFolder.Any(x => x.IsDirectory))
            {
                var file = new File
                {
                    Name = _config.RootFolderName,
                    MimeType = GoogleDriveFolderMime,
                    Parents = new List<string> { baseRoot }
                };
                var createRequest = new FilesResource.CreateRequest(_driveService, file) {QuotaUser = QuotaUser, SupportsTeamDrives = _config.SupportsTeamDrives};
                rootId = (await createRequest.ExecuteAsync()).Id;
                _logger.LogInformation($"New app root {_config.RootFolderName} created in '{_config.StorageRoot}'");
            }

            _logger.LogInformation($"Root Id : {rootId}");

            if (!isTeamDrive)
                await ShareWithAccountsAsync(rootId, _config.ShareWithAccount);

            return rootId;
        }
        private async Task ShareWithAccountsAsync(string fileId, string accounts)
        {
            if (string.IsNullOrEmpty(accounts)) return;

            var newEmails = accounts.Split(';', StringSplitOptions.RemoveEmptyEntries).Select(x=>x.Trim()).Distinct().ToArray();
            _logger.LogInformation($"Sharing file {fileId} with {accounts}.");

            var folder = await new FilesResource.GetRequest(_driveService, fileId) {Fields = "id,permissions", QuotaUser = QuotaUser}.ExecuteAsync();
            var remove = folder.Permissions.Where(x => !newEmails.Contains(x.EmailAddress) && x.EmailAddress != _config.CredentialParameters.ClientEmail).Select(x => _driveService.Permissions.Delete(folder.Id, x.Id)).ToList();
            var add = newEmails.Except(folder.Permissions.Select(x => x.EmailAddress))
                .Select(x => new PermissionsResource.CreateRequest(_driveService, new Permission {EmailAddress = x, Type = "user", Role = "reader"}, folder.Id)
                {
                    QuotaUser = QuotaUser,
                    SendNotificationEmail = false
                }).ToList();

            var cb = DefaultBatchCallback<Permission>();
            var batch = new BatchRequest(_driveService);
            remove.ForEach(x => batch.Queue(x, cb));
            add.ForEach(x => batch.Queue(x, cb));
            await batch.ExecuteAsync();
        }
        #endregion

        #region upload
        public Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data) => UploadFileAsync(fileName, data, null, null);

        public Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data, string description) => UploadFileAsync(fileName, data, description, null);

        public Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data, object properties) => UploadFileAsync(fileName, data, null, properties);

        public Task<IGoogleDriveFile> UploadFileAsync(string fileName, Stream data, string description, object properties)
        {
            var props = properties is IDictionary<string, object> dict
                ? dict.ToDictionary(x => x.Key, x => x.Value.ToString())
                : properties?.GetType().GetProperties().ToDictionary(x => x.Name, x => x.GetValue(properties)?.ToString());
            string ct = null;
            if (props != null && props.ContainsKey(ContentTypePropertyName))
            {
                ct = props[ContentTypePropertyName];
                props.Remove(ContentTypePropertyName);
            }

            return InternalUploadFileAsync(fileName, data, ct, description, props);
        }
        
        private async Task<IGoogleDriveFile> InternalUploadFileAsync(string fileName, Stream data, string contentType, string description, IDictionary<string, string> properties)
        {
            var file = new File
            {
                Name = fileName,
                Parents = new List<string> { RootId.Value.Result },
                Properties = properties,
                Description = description
            };
            var uploadReq = new FilesResource.CreateMediaUpload(_driveService, file, data, contentType)
            {
                Fields = GoogleDriveFileFieldList,
                QuotaUser = QuotaUser,
                SupportsTeamDrives = _config.SupportsTeamDrives
            };
            Exception lastException = null;
            for(var i = 0; i <= 7; i++)
            {
                if (i != 0) _logger.LogInformation($"Retrying upload: {fileName}. Try # {i + 1}");
                var uploadResult = await uploadReq.UploadAsync();
                lastException = uploadResult.Exception;
                if (lastException == null) break;
                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, i)));
                _logger.LogInformation($"Retrying upload: {fileName} in {Math.Pow(2, i)} sec");
            }
            if (lastException != null) throw new ApplicationException(lastException.Message, lastException);
            _logger.LogInformation($"Uploaded {fileName} : {uploadReq.ResponseBody.Id}");
            return GoogleDriveFile.Create(uploadReq.ResponseBody, this);
        }

        #endregion

        #region utils
        public async Task<(long Limit, long Usage, long UsageInDrive, long UsageInDriveTrash)> GetStorageQuota()
        {
            var req = _driveService.About.Get();
            req.Fields = "storageQuota";
            var result = await req.ExecuteAsync();
            return (result.StorageQuota.Limit ?? -1, result.StorageQuota.Usage ?? -1, result.StorageQuota.UsageInDrive ?? -1, result.StorageQuota.UsageInDriveTrash ?? -1);
        }
        #endregion

        #region helpers
        private TU[] RequestRunner<T, TU>(IEnumerable<T> requests, bool ignoreNotFound = true, Func<T, string> msgBuiler = null) where T : DriveBaseServiceRequest<TU>
        {
            var result = new List<TU>();
            Parallel.ForEach(requests,
                new ParallelOptions { MaxDegreeOfParallelism = _config.ParallelRequests },
                request =>
                {
                    var msg = msgBuiler?.Invoke(request) ?? $"{request.MethodName}";
                    try
                    {
                        result.Add(request.Execute());
                        msg += " - Ok";
                    }
                    catch (GoogleApiException ex) when (ex.HttpStatusCode == HttpStatusCode.NotFound && ignoreNotFound)
                    {
                        msg += $" - Failed: {ex.Message}";
                    }
                    _logger.LogInformation(msg);
                });
            return result.ToArray();
        }
        private PageStreamer<File, FilesResource.ListRequest, FileList, string> GetPageStreamer()
            => new PageStreamer<File, FilesResource.ListRequest, FileList, string>(
                (request, token) =>
                {
                    request.PageToken = token;
                    request.QuotaUser = QuotaUser;
                    request.SupportsTeamDrives = _config.SupportsTeamDrives;
                },
                response => response.NextPageToken,
                response => response.Files);

        private BatchRequest.OnResponse<T> DefaultBatchCallback<T>() where T : class => DefaultResultBatchCallback<T>(null);

        private BatchRequest.OnResponse<T> DefaultResultBatchCallback<T>(Action<T> contentHandler) where T : class
            => (content, error, index, message) =>
            {
                if (error != null) _logger.LogError($"Batch item {index} error: {error.Message}");
                if (content != null) contentHandler?.Invoke(content);
            };

        #endregion

        #region IGoogleDriveFile impl
        private class GoogleDriveFile : IGoogleDriveFile
        {
            public string Id { get; private set; }
            public bool Exists { get; private set; }
            public long Length { get; private set; }
            public string ContentUrl { get; private set; }
            public string Name { get; private set; }
            public DateTime LastModified { get; private set; }
            public DateTime Created { get; private set; }
            public bool IsDirectory => MimeType == GoogleDriveFolderMime;
            public string MimeType { get; private set; }
            public string Descrption { get; private set; }
            public IDictionary<string, string> Properties { get; private set; }
            public bool HasPreview { get; private set; }
            public string PreviewUrl { get; private set; }

            private GoogleDriveService Service { get; set; }

            public Task<Stream> GetContentStreamAsync()
            {
                if (!Exists) throw new ApplicationException($"Object {Id} does not exist in storage.");
                if (IsDirectory) throw new ApplicationException($"Object {Id} is Dirctory thus has no content.");
                Service._logger.LogInformation($"Retrieving content for {Id}");
                //note: not using webContent url since it might return 302 http responce
                var req = Service._driveService.Files.Get(Id);
                req.SupportsTeamDrives = Service._config.SupportsTeamDrives;
                var uri = new UriBuilder(req.CreateRequest().RequestUri.AbsoluteUri);
                if (uri.Query == null || uri.Query.Length <= 1)
                {
                    uri.Query = "alt=media";
                }
                else
                {
                    uri.Query = uri.Query.Substring(1) + "&alt=media";
                }
                return Service._driveService.HttpClient.GetStreamAsync(uri.Uri.AbsoluteUri);
            }

            public Task<Stream> GetContentPreviewStreamAsync()
            {
                if (!HasPreview) throw new ApplicationException($"Object {Id} has no preview.");
                Service._logger.LogInformation($"Retrieving preview for {Id}");
                return Service._driveService.HttpClient.GetStreamAsync(PreviewUrl);
            }

            public static GoogleDriveFile CreateNonExisting(string id) => new GoogleDriveFile {Id = id};
            public static GoogleDriveFile Create(File file, GoogleDriveService service) => new GoogleDriveFile
            {
                Service = service,
                Id = file.Id,
                Exists = true,
                Name = file.Name,
                ContentUrl = file.WebContentLink,
                LastModified = file.ModifiedTime ?? DateTime.Now,
                Created = file.CreatedTime ?? DateTime.Now,
                Length = file.Size ?? 0,
                MimeType = file.MimeType,
                HasPreview = file.HasThumbnail ?? false,
                Descrption = file.Description,
                PreviewUrl = file.ThumbnailLink,
                Properties = file.Properties ?? new Dictionary<string, string>()
            };
        }
        #endregion
    }
}
