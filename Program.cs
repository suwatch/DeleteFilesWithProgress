using System;
using System.IO;
using System.Threading;

namespace DeleteFilesWithProgress
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // DeleteFilesWithProgress.exe d:\home\logfiles\SalesForceIntegration
                if (args.Length == 0)
                {
                    Console.WriteLine(@"Usage: DeleteFilesWithProgress.exe d:\home\logfiles\SalesForceIntegration");
                    return;
                }

                // delete file older than 10 mins
                FileExtensions.DeleteIfOlderTime = DateTime.UtcNow.AddMinutes(-10);

                var path = new DirectoryInfo(args[0]);
                int folderCount;
                int filesCount;
                string largestFile;
                long largestFileSizeInBytes;
                string largestFolder;
                int largestFolderChildrenCount;
                int deletedFileCount = 1;
                bool incompleteScan;
                var size = FileExtensions.GetDirectorySizeInBytes(
                    path: path.FullName,
                    skipSymLink: true,
                    continueOnError: false,
                    cancellationToken: CancellationToken.None,
                    maxItemCount: 10000,
                    pauseInterval: 100,
                    folderCount: out folderCount,
                    filesCount: out filesCount,
                    largestFile: out largestFile,
                    largestFileSizeInBytes: out largestFileSizeInBytes,
                    largestFolder: out largestFolder,
                    largestFolderChildrenCount: out largestFolderChildrenCount,
                    deletedFileCount: out deletedFileCount,
                    incompleteScan: out incompleteScan);

                Console.WriteLine("size: {0:n0} bytes", size);
                Console.WriteLine("folderCount: {0:n0} folders", folderCount);
                Console.WriteLine("filesCount: {0:n0} files", filesCount);
                Console.WriteLine("largestFile: {0}", largestFile);
                Console.WriteLine("largestFileSize: {0:n0} bytes", largestFileSizeInBytes);
                Console.WriteLine("largestFolder: {0}", largestFolder);
                Console.WriteLine("largestFolderChildrenCount: {0:n0} items", largestFolderChildrenCount);
                Console.WriteLine("deletedFileCount: {0:n0} files", deletedFileCount);
                Console.WriteLine("incompleteScan: {0}", incompleteScan);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
