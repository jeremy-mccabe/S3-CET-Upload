using System;
using System.IO.Compression;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Amazon.S3;
using Amazon.S3.Transfer;

/// REMINDER: Credentials are saved in the config file!
/// 
/// UPDATE ON NEW RUN:
/// 
/// -workingDir: create a file path for a directory that contains all content for compression, encrption, and transfer.
/// ie: C:/Users/MyName/Desktop/S3Contents/
/// 
/// -keyName: name used for AWS object creation on S3.
/// ie: Packaged-AWS-Object
/// 
/// -bucketName: name of the S3 bucket on AWS cloud.
/// ie: myAmazonUserName.testbucket1
/// 
/// -bucketRegion: specifies endpoint for AWS bucket.
/// RegionEndpoint.USEast1
/// 
/// -targetDir: the name of the directory that you want to compress, encrypt, transfer.
/// ie: Target-Dir
/// 
/// -password: key used for AES encryption.
/// ie: p-a-s-s-w-o-r-d
/// 
/// -startPath, zipPath, FileEncrypt, encryption_path, ZipPathForDeletion:
/// all need to be updated with the same string as workingDir (needs @ in front of string)
/// 
/// 


namespace Amazon.Upload
{
    class UploadProgram
    {

        //  Call this function to remove the key from memory after use for security
        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        public static extern bool ZeroMemory(IntPtr Destination, int Length);

        // AWS PARAMETERS:
        // If name already exists, will not be overwritten (version control will auto save new version):
        private const string bucketName = "C:/Users/jeremy/Desktop/TargetDir/";
        // creates name for object, will use file name if none specified:
        private const string keyName = "Packaged-AWS-Object";
        // working directory that contains all S3/Compression/Encryption files:
        private const string workingDir = "myAmazonUserName.testbucket1";
        // file name to attach to object file path:
        private const string packagedFile = "Zipped-Dir.zip.aes";
        // identifies object file path to create an AWS object:
        private const string filePath = workingDir + packagedFile;
        // specify bucket region:
        private static readonly RegionEndpoint bucketRegion = RegionEndpoint.USEast1;
        // interface for accessing S3:
        private static IAmazonS3 s3Client;

 
        // Creates a random salt that will be used to encrypt your file. This method is required on FileEncrypt.
        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    // Fill the buffer with the generated data.
                    rng.GetBytes(data);
                }
            }

            return data;
        }

        public static void Main(string[] args)
        {

            // COMPRESSION - MSDN
            /// directory you want to zip:
            string targetDir = "Target-Dir";
            /// zipped directory created from target directory:
            string zipDir = "Zipped-Dir.zip";

            // try-catch block:
            try
            {
                // identifies target directory and target path:
                string startPath = @"C:\Users\jeremy\Desktop\TargetDir\" + targetDir;
                Console.WriteLine("Folder was identified as target directory:\t" + targetDir);

                // decides on a destination for zipped directory:
                string zipPath = @"C:\Users\jeremy\Desktop\TargetDir\" + zipDir;
                Console.WriteLine("Zip path identified:\t\t\t\t" + zipPath);

                // creates new zipped directory:
                ZipFile.CreateFromDirectory(startPath, zipPath, CompressionLevel.Fastest, false);
                Console.WriteLine("Zip archive:\t\t\t\t\t'" + zipDir + "' successfully created.");

            }
            catch (System.IO.DirectoryNotFoundException e1)
            {
                string s = e1.Message;
                Console.WriteLine("EXCEPTION THROWN: " + s);
            }
            catch (System.IO.IOException e2)
            {
                string s = e2.Message;
                Console.WriteLine("EXCEPTION THROWN: " + s);
            }


            // RIJNDAEL_ENCRYPTION call:

            string password = "p-a-s-s-w-o-r-d";
            // For additional security Pin the password of your files
            GCHandle gch = GCHandle.Alloc(password, GCHandleType.Pinned);
            // Encrypt the file:
            FileEncrypt(@"C:\Users\jeremy\Desktop\TargetDir\" + zipDir, password);
            // To increase the security of the encryption, delete the given password from the memory !
            ZeroMemory(gch.AddrOfPinnedObject(), password.Length * 2);
            gch.Free();
            // You can verify it by displaying its value later on the console (the password won't appear)
            // Console.WriteLine("The given password is surely nothing: " + password);

            // identifies encryption path:
            string encryption_path = @"C:\Users\jeremy\Desktop\TargetDir\" + packagedFile;

            // identifies victim file for deletion (compressed file) after it's been compressed:
            string zipPathForDeletion = @"C:\Users\jeremy\Desktop\TargetDir\" + zipDir;

            File.Delete(zipPathForDeletion);
            Console.WriteLine("File:\t\t\t\t\t\t'" + zipDir + "' successfully deleted.");

            // TRANSFER (Upload) - AWS
            // Object instantiation and upload function:
            s3Client = new AmazonS3Client(bucketRegion);
            UploadFileAsync().Wait();

            // identifies victim file for deletion (packaged file) after it's been uploaded:
            File.Delete(encryption_path);
            Console.WriteLine("File:\t\t\t\t\t\t'" + packagedFile + "' successfully deleted.");

        } // end Main function


        // RIJNDAEL_ENCRYPTION definition:
        // Encrypts a file from its path and a plain password.

        private static void FileEncrypt(string inputFile, string password)
        {
            //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            FileStream fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            // http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            // Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            // write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    // Application.DoEvents();
                    cs.Write(buffer, 0, read);
                }

                // Close up
                fsIn.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }

        // Old AES_ENCRYPTION definition:
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {

            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an AES object
            // with the specified key and IV.
            using (Aes aesAlg = AesManaged.Create())
            {
                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                // Should set Key and IV here.  Good approach: 
                // derive them from a password via Cryptography.Rfc2898DeriveBytes 
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        // static AWS asynchronous upload function:
        private static async Task UploadFileAsync()
        {

            try
            {
                var fileTransferUtility = new TransferUtility(s3Client);

                // Option 2. Specify object key name explicitly:
                await fileTransferUtility.UploadAsync(filePath, bucketName, keyName);
                Console.WriteLine("AWS file upload:\t\t\t\t" + "Completed.");

            }
            catch (AmazonS3Exception e)
            {
                Console.WriteLine("Error encountered on server. Message:'{0}' when writing an object", e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine("Unknown encountered on server. Message:'{0}' when writing an object", e.Message);
            }

        }

    } // end UploadFileMPUHighLevelAPITest class

} // end Amazon.Upload namespace
