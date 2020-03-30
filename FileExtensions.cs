using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace DeleteFilesWithProgress
{
    public static class FileExtensions
    {
        public static DateTime DeleteIfOlderTime = DateTime.MinValue;

        // Every file/folder will be charged an extra 1K for file system metadata.
        // REMARKS: FSRM uses the same logic for calculating usage which 
        // helps blocking tenants to store a bunch of files with no data since
        // they can still fill their quota.
        public const int FileSystemMetadataSize = 1024;

        public static void CreateTextFile(string filePath, string fileContents)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new ArgumentNullException("filePath");
            }

            File.WriteAllText(filePath, fileContents, Encoding.UTF8);
        }

        public static bool DeleteDirectory(string path, bool throwIfError = false)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException("path");
            }

            return DeleteDirectoryInternal(path, throwIfError);
        }

        public static bool DeleteFile(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException("path");
            }

            return DeleteFileInternal(path, false);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private static bool DeleteDirectoryInternal(string path, bool throwIfError)
        {
            string longPath = ToLongPath(path);

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa363866%28v=vs.85%29.aspx
            // To remove a symbolic link, delete the file (using DeleteFile or similar APIs) 
            // or remove the directory (using RemoveDirectory or similar APIs) depending 
            // on what type of symbolic link is used
            // IMPORTANT: this is an important code path, since it can delete customer's data given enough permissions
            // and failure to detect a symlink
            if (!IsPathWithReparsePoint(longPath))
            {
                foreach (string directory in FindDirectories(longPath))
                {
                    DeleteDirectoryInternal(directory, throwIfError);
                }
                foreach (string file in FindFiles(longPath))
                {
                    DeleteFileInternal(file, throwIfError);
                }
            }

            SetFileAttributes(longPath, FileAttributes.Normal, throwIfError);
            bool ret = NativeMethods.RemoveDirectoryW(longPath);
            if (!ret)
            {
                GetWin32Error(longPath, throwIfError);
            }
            return ret;
        }

        private static string ToLongPath(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                return path;
            }
            if (path.StartsWith(@"\\", StringComparison.Ordinal))
            {
                return (@"\\?\UNC\" + path.Substring(2));
            }
            return (@"\\?\" + path);
        }

        private static string ToShortPath(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            {
                return path.Replace(@"\\?\", "");
            }
            return path;
        }

        [SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private static string GetWin32Error(string path, bool throwIfError)
        {
            string message = null;
            int errorCode = Marshal.GetLastWin32Error();
            if (errorCode != 0)
            {
                message = new Win32Exception(errorCode).Message + " : " + path;
                Console.WriteLine(message);
                if (throwIfError)
                {
                    throw new IOException(message);
                }
            }
            return message;
        }

        [SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private static bool SetFileAttributes(string path, FileAttributes fileAttributes, bool throwIfError)
        {
            bool ret = NativeMethods.SetFileAttributesW(path, (int)fileAttributes);
            if (!ret)
            {
                GetWin32Error(path, throwIfError);
            }
            return ret;
        }

        [SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static bool DeleteFileInternal(string path, bool throwIfError)
        {
            string longPath = ToLongPath(path);
            SetFileAttributes(longPath, FileAttributes.Normal, throwIfError);
            bool ret = NativeMethods.DeleteFileW(longPath);
            if (!ret)
            {
                GetWin32Error(longPath, throwIfError);
            }
            return ret;
        }

        public static List<string> FindFiles(string path)
        {
            return Find(path, false, true);
        }

        public static List<string> FindDirectories(string path)
        {
            return Find(path, true, false);
        }

        private static List<string> Find(string path, bool includeDirectories, bool includeFiles)
        {
            List<string> results = new List<string>();
            NativeMethods.WIN32_FIND_DATAW findData;
            string searchPath = path;
            if (!path.EndsWith("\\", StringComparison.Ordinal))
            {
                searchPath = searchPath + "\\";
            }
            searchPath = searchPath + "*.*";

            IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            IntPtr findHandle = NativeMethods.FindFirstFileW(searchPath, out findData);
            if (findHandle != INVALID_HANDLE_VALUE)
            {
                bool found = false;
                do
                {
                    string currentFileName = findData.cFileName;
                    string currentFileFullPath = Path.Combine(path, currentFileName);

                    // do not include directories and files of symlink targets
                    if (IsPathWithReparsePoint(currentFileFullPath))
                    {
                        // include just the symlink, so it is deleted, but the target directories and files are not
                        if (includeDirectories)
                        {
                            results.Add(currentFileFullPath);
                        }
                    }
                    else
                    {
                        if (((int)findData.dwFileAttributes & NativeMethods.FILE_ATTRIBUTE_DIRECTORY) != 0)
                        {
                            // add child directory files
                            if (currentFileName != "." && currentFileName != "..")
                            {
                                string fullPath = path;
                                if (!fullPath.EndsWith("\\", StringComparison.Ordinal))
                                {
                                    fullPath = fullPath + "\\";
                                }
                                fullPath = fullPath + currentFileName;
                                List<string> childResults = Find(fullPath, includeDirectories, includeFiles);
                                results.AddRange(childResults);

                                if (includeDirectories)
                                {
                                    results.Add(currentFileFullPath);
                                }
                            }
                        }
                        else
                        {
                            // add file
                            if (includeFiles)
                            {
                                results.Add(currentFileFullPath);
                            }
                        }
                    }

                    found = NativeMethods.FindNextFileW(findHandle, out findData);
                }
                while (found);
            }
            NativeMethods.FindClose(findHandle);
            return results;
        }

        //public static long GetDirectorySizeInBytes(string path, out int folderCount, out int filesCount, bool continueOnError)
        //{
        //    return GetDirectorySizeInBytes(path, skipSymLink: false, continueOnError: continueOnError, folderCount: out folderCount, filesCount: out filesCount);
        //}

        //public static long GetDirectorySizeInBytes(string path, bool skipSymLink, bool continueOnError, out int folderCount, out int filesCount)
        //{
        //    return GetDirectorySizeInBytes(
        //        path, skipSymLink, continueOnError, CancellationToken.None,
        //        maxItemCount: -1, pauseInterval: 0,
        //        folderCount: out folderCount, filesCount: out filesCount,
        //        largestFile: out _, largestFileSizeInBytes: out _, largestFolder: out _, largestFolderChildrenCount: out _,
        //        incompleteScan: out _);
        //}

        /// <summary>
        /// This method is optimized to avoid recursion and we use pinvoke to retrieve the file attributes in the same call since 
        /// performance is critical for this routine.
        /// </summary>
        public static long GetDirectorySizeInBytes(
            string path, bool skipSymLink, bool continueOnError, CancellationToken cancellationToken,
            int maxItemCount, int pauseInterval, out int folderCount, out int filesCount,
            out string largestFile, out long largestFileSizeInBytes,
            out string largestFolder, out int largestFolderChildrenCount,
            out int deletedFileCount, out bool incompleteScan)
        {
            Console.Write($"{DateTime.UtcNow:s}");
            IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            int currentDeletedFileCount = 0;

            largestFile = null;
            largestFileSizeInBytes = 0;
            largestFolder = null;
            largestFolderChildrenCount = 0;
            incompleteScan = true;
            deletedFileCount = 0;

            List<string> toDeletes = new List<string>();

            Queue<string> foldersQueue = new Queue<string>();
            foldersQueue.Enqueue(path);

            folderCount = filesCount = 0;
            long size = 0;
            while (foldersQueue.Count > 0)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return size;
                }

                string currentFolder = foldersQueue.Dequeue();

                int childrenCount = 0;
                NativeMethods.WIN32_FIND_DATAW findData;
                IntPtr handle = IntPtr.Zero;

                try
                {
                    // Uses a larger buffer for directory queries, which can increase performance of the find operation.
                    handle = NativeMethods.FindFirstFileExW(ToLongPath(currentFolder).TrimEnd('\\') + @"\*",
                        NativeMethods.FINDEX_INFO_LEVELS.FindExInfoBasic, // does not query the short file name, improving overall enumeration speed
                        out findData,
                        NativeMethods.FINDEX_SEARCH_OPS.FindExSearchNameMatch,
                        IntPtr.Zero,
                        NativeMethods.FIND_FIRST_EX_LARGE_FETCH);

                    if (handle == INVALID_HANDLE_VALUE)
                    {
                        int error = Marshal.GetLastWin32Error();
                        string message = string.Format("{0}. {1}", new Win32Exception(error).Message, currentFolder);

                        Win32Exception exception = new Win32Exception(error, message);
                        exception.Data.Add("Method", "FindFirstFile");
                        exception.Data.Add("Error", "INVALID_HANDLE_VALUE");
                        exception.Data.Add("Path", currentFolder);

                        throw exception;
                    }

                    do
                    {
                        // Pause for a little while to avoid spinning 100% CPU when enumerating a large directory, if requested.
                        if (pauseInterval > 1 && (folderCount + filesCount + 1) % pauseInterval == 0)
                        {
                            if ((folderCount + filesCount + 1) % (pauseInterval * 5) == 0)
                            {
                                Console.WriteLine();
                                Console.Write($"{DateTime.UtcNow:s}({deletedFileCount - currentDeletedFileCount} files deleted)");
                                currentDeletedFileCount = deletedFileCount;
                            }
                            Console.Write('.');
                            Thread.Sleep(100);
                        }

                        if (cancellationToken.IsCancellationRequested)
                        {
                            return size;
                        }

                        if ((findData.dwFileAttributes & FileAttributes.Directory) != 0)
                        {
                            // this is a directory
                            if (skipSymLink && (findData.dwFileAttributes & FileAttributes.ReparsePoint) != 0)
                            {
                                // We want to skip symlinks when directed to
                                continue;
                            }

                            if (findData.cFileName != "." && findData.cFileName != "..")
                            {
                                // count the folder
                                folderCount++;
                                childrenCount++;

                                // Every folder will be charged an extra 1K for file system metadata.
                                // REMARKS: FSRM uses the same logic for calculating usage which 
                                // helps blocking tenants to store a bunch of folders since
                                // they can still fill their quota.
                                size += FileSystemMetadataSize;

                                foldersQueue.Enqueue(currentFolder.TrimEnd('\\') + "\\" + findData.cFileName);

                                // Impose a limit on the total number of items we will go through.
                                if (maxItemCount != -1 && (folderCount + filesCount > maxItemCount))
                                {
                                    Console.WriteLine("Hit max limit " + maxItemCount + " items!");
                                    return size;
                                }
                            }

                            continue;
                        }

                        var ftLastWriteTime = ((long)findData.ftLastWriteTime.dwHighDateTime << 32) + findData.ftLastWriteTime.dwLowDateTime;
                        var lastWriteTime = DateTime.FromFileTimeUtc(ftLastWriteTime);
                        var toDelete = lastWriteTime < DeleteIfOlderTime;
                        if (toDelete)
                        {
                            toDeletes.Add(currentFolder.TrimEnd('\\') + "\\" + findData.cFileName);
                            if (toDeletes.Count >= 25)
                            {
                                var deleted = 0;
                                Parallel.ForEach(toDeletes, f =>
                                {
                                    if (FileExtensions.DeleteFileInternal(f, throwIfError: false))
                                    {
                                        Interlocked.Increment(ref deleted);
                                    }
                                });

                                deletedFileCount += deleted;

                                toDeletes.Clear();
                            }
                        }

                        // count the file
                        filesCount++;
                        childrenCount++;

                        // get file size and aggregate the value
                        long filesize = (long)findData.nFileSizeHigh << 32 | (long)findData.nFileSizeLow;
                        size += filesize;

                        // Track file with the largest size.
                        if (filesize > largestFileSizeInBytes)
                        {
                            largestFile = Path.Combine(currentFolder, findData.cFileName);
                            largestFileSizeInBytes = filesize;
                        }

                        // Every file will be charged an extra 1K for file system metadata.
                        // REMARKS: FSRM uses the same logic for calculating usage which 
                        // helps blocking tenants to store a bunch of files with no data since
                        // they can still fill their quota.
                        size += FileSystemMetadataSize;

                        // Impose a limit on the total number of items we will go through.
                        if (maxItemCount != -1 && (folderCount + filesCount > maxItemCount))
                        {
                            return size;
                        }
                    }
                    while (NativeMethods.FindNextFileW(handle, out findData));

                    // Track folder with the most items.
                    if (childrenCount > largestFolderChildrenCount)
                    {
                        largestFolder = currentFolder;
                        largestFolderChildrenCount = childrenCount;
                    }
                }
                catch (Exception ex)
                {
                    if (continueOnError)
                    {
                        // log and continue
                        Console.WriteLine(ex);
                    }
                    else
                    {
                        throw;
                    }
                }
                finally
                {
                    if (handle != IntPtr.Zero && handle != INVALID_HANDLE_VALUE)
                    {
                        NativeMethods.FindClose(handle);
                    }

                    handle = IntPtr.Zero;
                }
            }

            incompleteScan = false;
            return size;
        }

        public static void VisitDirectory(string path, Action<string> onVisitDirectory, Action<string> onVisitFile)
        {
            IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

            Queue<string> foldersQueue = new Queue<string>();
            foldersQueue.Enqueue(path);

            while (foldersQueue.Count > 0)
            {
                string currentFolder = foldersQueue.Dequeue();

                onVisitDirectory(currentFolder);

                NativeMethods.WIN32_FIND_DATAW findData;

                // Uses a larger buffer for directory queries, which can increase performance of the find operation.
                IntPtr handle = NativeMethods.FindFirstFileExW(ToLongPath(currentFolder).TrimEnd('\\') + @"\*",
                    NativeMethods.FINDEX_INFO_LEVELS.FindExInfoBasic, // does not query the short file name, improving overall enumeration speed
                    out findData,
                    NativeMethods.FINDEX_SEARCH_OPS.FindExSearchNameMatch,
                    IntPtr.Zero,
                    NativeMethods.FIND_FIRST_EX_LARGE_FETCH);

                try
                {
                    if (handle == INVALID_HANDLE_VALUE)
                    {
                        Win32Exception exception = new Win32Exception();
                        exception.Data.Add("Method", "FindFirstFile");
                        exception.Data.Add("Error", "INVALID_HANDLE_VALUE");
                        exception.Data.Add("Path", currentFolder);

                        throw exception;
                    }

                    do
                    {
                        if ((findData.dwFileAttributes & FileAttributes.Directory) != 0)
                        {
                            // this is a directory
                            if (findData.cFileName != "." && findData.cFileName != "..")
                            {
                                foldersQueue.Enqueue(currentFolder.TrimEnd('\\') + "\\" + findData.cFileName);
                            }

                            continue;
                        }

                        onVisitFile(currentFolder.TrimEnd('\\') + "\\" + findData.cFileName);
                    }
                    while (NativeMethods.FindNextFileW(handle, out findData));
                }
                finally
                {
                    if (handle != IntPtr.Zero && handle != INVALID_HANDLE_VALUE)
                    {
                        NativeMethods.FindClose(handle);
                    }

                    handle = IntPtr.Zero;
                }
            }
        }

        public static bool IsPathWithReparsePoint(string path)
        {
            path = ToShortPath(path);
            return !string.IsNullOrEmpty(path) && (File.Exists(path) || Directory.Exists(path)) &&
                   ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0);
        }

        [SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        public static bool TryGetSymbolicLinkTargetPath(string symbolicLinkPath, out string targetPath)
        {
            try
            {
                using (SafeFileHandle handle = OpenReparsePoint(symbolicLinkPath, NativeMethods.EFileAccess.GenericRead))
                {
                    targetPath = GetSymbolicLinkTargetInternal(handle);
                    return !string.IsNullOrEmpty(targetPath);
                }
            }
            // This is what we have for figuring out whether a given path is symlink or not.
            // Both methods OpenReparsePoint or GetSymbolicLinkTargetInternal can throw different exceptions
            // when they try to open a given path as a symlink and get a target path from it.
            // For now, catch all for not-a-symlink case. The proper fix would be to better the logic of determining
            // whether a path is a symlink or not
            catch (Exception)
            {
                targetPath = null;
            }

            return false;
        }

        [SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private static SafeFileHandle OpenReparsePoint(string reparsePoint, NativeMethods.EFileAccess accessMode)
        {
            SafeFileHandle reparsePointHandle = NativeMethods.CreateFile(reparsePoint, accessMode,
                NativeMethods.EFileShare.Read | NativeMethods.EFileShare.Write | NativeMethods.EFileShare.Delete,
                IntPtr.Zero, NativeMethods.ECreationDisposition.OpenExisting,
                NativeMethods.EFileAttributes.BackupSemantics | NativeMethods.EFileAttributes.OpenReparsePoint, IntPtr.Zero);

            if (Marshal.GetLastWin32Error() != 0)
            {
                ThrowLastWin32Error("Resources.UnableToOpenReparsePoint");
            }

            return reparsePointHandle;
        }

        [SuppressMessage("Microsoft.Security", "CA2135:SecurityRuleSetLevel2MethodsShouldNotBeProtectedWithLinkDemandsFxCopRule", Justification = "Partial Trust Scenarios Not Supported")]
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        private static string GetSymbolicLinkTargetInternal(SafeFileHandle handle)
        {
            int outBufferSize = Marshal.SizeOf(typeof(NativeMethods.REPARSE_DATA_BUFFER));
            IntPtr outBuffer = Marshal.AllocHGlobal(outBufferSize);

            try
            {
                int bytesReturned;
                bool result = NativeMethods.DeviceIoControl(handle, NativeMethods.FSCTL_GET_REPARSE_POINT,
                    IntPtr.Zero, 0, outBuffer, outBufferSize, out bytesReturned, IntPtr.Zero);

                if (!result)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == NativeMethods.ERROR_NOT_A_REPARSE_POINT)
                        return null;

                    ThrowLastWin32Error("Resources.UnableToGetJunctionPointInformation");
                }

                // Only look at the RepoartTag, this might be a Win32Interop.REPARSE_DATA_BUFFER_symlink
                NativeMethods.REPARSE_DATA_BUFFER rdb = (NativeMethods.REPARSE_DATA_BUFFER)Marshal.PtrToStructure(outBuffer, typeof(NativeMethods.REPARSE_DATA_BUFFER));

                string targetDir = null;

                if (rdb.ReparseTag == NativeMethods.IO_REPARSE_TAG_MOUNT_POINT)
                {
                    NativeMethods.REPARSE_DATA_BUFFER reparseDataBuffer = rdb;

                    targetDir = Encoding.Unicode.GetString(reparseDataBuffer.PathBuffer,
                        reparseDataBuffer.SubstituteNameOffset, reparseDataBuffer.SubstituteNameLength);
                }

                if (rdb.ReparseTag == NativeMethods.IO_REPARSE_TAG_SYMLINK)
                {
                    var reparseDataBuffer = (NativeMethods.REPARSE_DATA_BUFFER)Marshal.PtrToStructure(outBuffer, typeof(NativeMethods.REPARSE_DATA_BUFFER));
                    targetDir = Encoding.Unicode.GetString(reparseDataBuffer.PathBuffer, reparseDataBuffer.PrintNameOffset, reparseDataBuffer.PrintNameLength);
                }

                if (targetDir != null && targetDir.StartsWith(NativeMethods.NonInterpretedPathPrefix, StringComparison.Ordinal))
                {
                    targetDir = targetDir.Substring(NativeMethods.NonInterpretedPathPrefix.Length);
                }

                return targetDir;
            }
            finally
            {
                Marshal.FreeHGlobal(outBuffer);
            }
        }

        private static void ThrowLastWin32Error(string message)
        {
            throw new IOException(message, Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }
    }

    public enum ComputerNameFormat : int
    {
        /// <summary>
        /// The NetBIOS name of the local computer or the cluster associated with the local computer. This name is limited to MAX_COMPUTERNAME_LENGTH + 1 characters and may be a truncated version of the DNS host name. For example, if the DNS host name is "corporate-mail-server", the NetBIOS name would be "corporate-mail-".
        /// </summary>
        NetBIOS,
        /// <summary>
        /// The DNS name of the local computer or the cluster associated with the local computer.
        /// </summary>
        DnsHostname,
        /// <summary>
        /// The name of the DNS domain assigned to the local computer or the cluster associated with the local computer.
        /// </summary>
        DnsDomain,
        /// <summary>
        /// The fully qualified DNS name that uniquely identifies the local computer or the cluster associated with the local computer. 
        /// </summary>
        /// <remarks>
        /// This name is a combination of the DNS host name and the DNS domain name, using the form HostName.DomainName. For example, if the DNS host name is "corporate-mail-server" and the DNS domain name is "microsoft.com", the fully qualified DNS name is "corporate-mail-server.microsoft.com".
        /// </remarks>
        DnsFullyQualified,
        /// <summary>
        /// The NetBIOS name of the local computer. On a cluster, this is the NetBIOS name of the local node on the cluster.
        /// </summary>
        PhysicalNetBIOS,
        /// <summary>
        /// The DNS host name of the local computer. On a cluster, this is the DNS host name of the local node on the cluster.
        /// </summary>
        PhysicalDnsHostname,
        /// <summary>
        /// The name of the DNS domain assigned to the local computer. On a cluster, this is the DNS domain of the local node on the cluster.
        /// </summary>
        PhysicalDnsDomain,
        /// <summary>
        /// The fully qualified DNS name that uniquely identifies the computer. On a cluster, this is the fully qualified DNS name of the local node on the cluster. The fully qualified DNS name is a combination of the DNS host name and the DNS domain name, using the form HostName.DomainName.
        /// </summary>
        PhysicalDnsFullyQualified
    }

    [SuppressMessage("Microsoft.Security", "CA5122:PInvokesShouldNotBeSafeCriticalFxCopRule")]
    internal static class NativeMethods
    {
        public const int FIND_FIRST_EX_LARGE_FETCH = 2;
        public const int FILE_ATTRIBUTE_DIRECTORY = 0x10;
        public const int FSCTL_GET_REPARSE_POINT = 0x000900A8;
        public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        public const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;

        public const int ERROR_NOT_A_REPARSE_POINT = 4390;
        public const string NonInterpretedPathPrefix = @"\??\";

        [Flags]
        public enum EFileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,
        }

        [Flags]
        public enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004,
        }

        public enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5,
        }

        public enum FINDEX_INFO_LEVELS
        {
            FindExInfoStandard = 0,
            FindExInfoBasic = 1
        }

        public enum FINDEX_SEARCH_OPS
        {
            FindExSearchNameMatch = 0,
            FindExSearchLimitToDirectories = 1,
            FindExSearchLimitToDevices = 2
        }

        public enum LOGON_TYPE : int
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        public enum LogonProvider
        {
            LOGON32_PROVIDER_DEFAULT = 0,
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WIN32_FIND_DATAW
        {
            public FileAttributes dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x208)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x1c)]
            public string cAlternateFileName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct REPARSE_DATA_BUFFER
        {
            /// <summary>
            /// Reparse point tag. Must be a Microsoft reparse point tag.
            /// </summary>
            public uint ReparseTag;

            /// <summary>
            /// Size, in bytes, of the data after the Reserved member. This can be calculated by:
            /// (4 * sizeof(ushort)) + SubstituteNameLength + PrintNameLength + 
            /// (namesAreNullTerminated ? 2 * sizeof(char) : 0);
            /// </summary>
            public ushort ReparseDataLength;

            /// <summary>
            /// Reserved; do not use. 
            /// </summary>
            public ushort Reserved;

            /// <summary>
            /// Offset, in bytes, of the substitute name string in the PathBuffer array.
            /// </summary>
            public ushort SubstituteNameOffset;

            /// <summary>
            /// Length, in bytes, of the substitute name string. If this string is null-terminated,
            /// SubstituteNameLength does not include space for the null character.
            /// </summary>
            public ushort SubstituteNameLength;

            /// <summary>
            /// Offset, in bytes, of the print name string in the PathBuffer array.
            /// </summary>
            public ushort PrintNameOffset;

            /// <summary>
            /// Length, in bytes, of the print name string. If this string is null-terminated,
            /// PrintNameLength does not include space for the null character. 
            /// </summary>
            public ushort PrintNameLength;

            /// <summary>
            /// A buffer containing the unicode-encoded path string. The path string contains
            /// the substitute name string and print name string.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3FF0)]
            public byte[] PathBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct REPARSE_DATA_BUFFER_symlink
        {
            /// <summary>
            /// Reparse point tag. Must be a Microsoft reparse point tag.
            /// </summary>
            public uint ReparseTag;

            /// <summary>
            /// Size, in bytes, of the data after the Reserved member. This can be calculated by:
            /// (4 * sizeof(ushort)) + SubstituteNameLength + PrintNameLength + 
            /// (namesAreNullTerminated ? 2 * sizeof(char) : 0);
            /// </summary>
            public ushort ReparseDataLength;

            /// <summary>
            /// Reserved; do not use. 
            /// </summary>
            public ushort Reserved;

            /// <summary>
            /// Offset, in bytes, of the substitute name string in the PathBuffer array.
            /// </summary>
            public ushort SubstituteNameOffset;

            /// <summary>
            /// Length, in bytes, of the substitute name string. If this string is null-terminated,
            /// SubstituteNameLength does not include space for the null character.
            /// </summary>
            public ushort SubstituteNameLength;

            /// <summary>
            /// Offset, in bytes, of the print name string in the PathBuffer array.
            /// </summary>
            public ushort PrintNameOffset;

            /// <summary>
            /// Length, in bytes, of the print name string. If this string is null-terminated,
            /// PrintNameLength does not include space for the null character. 
            /// </summary>
            public ushort PrintNameLength;

            /// <summary>
            /// Reparsepoint flags 
            /// </summary>
            public uint Flags;

            /// <summary>
            /// A buffer containing the unicode-encoded path string. The path string contains
            /// the substitute name string and print name string.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3FF0)]
            public byte[] PathBuffer;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LogonUser(
            [MarshalAs(UnmanagedType.LPWStr)]string username,
            [MarshalAs(UnmanagedType.LPWStr)]string domain,
            [MarshalAs(UnmanagedType.LPWStr)]string password,
            LOGON_TYPE logonType,
            LogonProvider logonProvider,
            out SafeFileHandle token);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool RemoveDirectoryW([MarshalAs(UnmanagedType.LPWStr)] string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeleteFileW([MarshalAs(UnmanagedType.LPWStr)] string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetFileAttributesW([MarshalAs(UnmanagedType.LPWStr)] string path, int attr);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr FindFirstFileW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern IntPtr FindFirstFileExW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, out WIN32_FIND_DATAW lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, IntPtr lpSearchFilter, int dwAdditionalFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeviceIoControl(SafeFileHandle device, uint dwIoControlCode,
            IntPtr InBuffer, int nInBufferSize,
            IntPtr OutBuffer, int nOutBufferSize,
            out int pBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            string lpFileName,
            EFileAccess dwDesiredAccess,
            EFileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            ECreationDisposition dwCreationDisposition,
            EFileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetComputerNameEx(
            ComputerNameFormat NameType,
            [Out] StringBuilder lpBuffer,
            ref int lpnSize);
    }
}
