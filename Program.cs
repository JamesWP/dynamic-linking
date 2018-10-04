using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

namespace simple_dotnet
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"{String.Join(',', args)}"); 
            if (args.Length < 1) return;

            var filename = args[0];
            var certificate = File.ReadAllText(filename);

            Console.WriteLine("Hello World!");
            Console.WriteLine($"cert: {certificate}");

            var inbio = BIO_new(BIO_s_mem());
            Console.WriteLine($"inbio: 0x{inbio.ToString("X16")}");
            
            var outbio = BIO_new(BIO_s_mem());
/*
            var instr1 = "hello world from c#";
            var instr1_l = BIO_puts(inbio, instr1, instr1.Length);
            Console.WriteLine($"{instr1_l}");

            var instr2 = " moar text";
            var instr2_l = BIO_write(inbio, instr2, instr2.Length); 
*/
            var cert_write_len = BIO_write(inbio, certificate, certificate.Length);
            if (cert_write_len != certificate.Length) { Console.WriteLine("cert lenght mismatch"); }

            var cert = PEM_read_bio_X509(inbio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine($"cert: 0x{cert.ToString("X16")}");

            var pkey = X509_get_pubkey(cert); 
            Console.WriteLine($"pkey: 0x{pkey.ToString("X16")}");

            var bits = EVP_PKEY_bits(pkey).ToString();
            Console.WriteLine($"bits: {bits}");
            
            BIO_write(outbio, bits, bits.Length); 
            BIO_write(outbio, "\n\n", "\n\n".Length);
      
            PEM_write_bio_PUBKEY(outbio, pkey);

            var readbuf = new byte[2048];
            var readbuf_l = BIO_read(outbio, readbuf, readbuf.Length);
            Console.WriteLine($"{readbuf_l} chars read '{Encoding.ASCII.GetString(readbuf, 0, readbuf_l)}'");

            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free_all(inbio);
        }

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern IntPtr BIO_s_mem();

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern IntPtr BIO_new(IntPtr a);
        
        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern int BIO_puts(IntPtr a, 
                                          [MarshalAs(UnmanagedType.LPStr)] string b,
                                          int c);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern int BIO_read(IntPtr a, [Out] byte[] b, int c);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern int BIO_write(IntPtr a, [MarshalAs(UnmanagedType.LPStr)] string b, int c);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern void BIO_free_all(IntPtr a);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern IntPtr PEM_read_bio_X509(IntPtr a, [Out] IntPtr b, IntPtr c, IntPtr d);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern IntPtr X509_get_pubkey(IntPtr a);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern void EVP_PKEY_free(IntPtr a);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern int EVP_PKEY_bits(IntPtr a);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern void X509_free(IntPtr a);

        [DllImport("/lib/x86_64-linux-gnu/libcrypto.so.1.0.0")]
        public static extern int PEM_write_bio_PUBKEY(IntPtr a, IntPtr b);
    }
}
