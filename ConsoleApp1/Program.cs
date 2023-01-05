using BitConverter;
using System.Diagnostics;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Debug.WriteLine(((12 * 352 + 2 * 44100) % 4294967296).ToString());
            Console.ReadKey();
        }
    }
}