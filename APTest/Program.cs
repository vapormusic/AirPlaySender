using APLibrary;
using APLibrary.AirPlay.Types;
using static System.Net.Mime.MediaTypeNames;
using System.Diagnostics;

namespace APTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
                var airtunes = new APLibrary.AirPlayClient();
                var host = "192.168.100.12";
                string[] argvtxt = new string[] { 
                    //"tp=UDP", "sm=false", "sv=false", "ek=1", "et=0,1", "md=0,1,2", "cn=0,1", "ch=2", "ss=16", "sr=44100", "pw=false", "vn=3", "txtvers=1" 
                     "cn=0,1,2,3",
    "da=true",
    "et=0,3,5",
    "ft=0x4A7FCA00,0xBC354BD0",
    "sf=0x80404",
    "md=0,1,2",
    "am=AudioAccessory5,1",
    "pk=lolno",
    "tp=UDP",
    "vn=65537",
    "vs=610.20.41",
    "ov=15.4.1",
    "vv=2"

                };
                var argsoptions = new AirTunesOptions();
                argsoptions.port = 7000;
                argsoptions.txt = argvtxt;
                argsoptions.volume = 40;
                //argsoptions.airplay2 = true;
                var device = airtunes.add(host, argsoptions);

                void Device_emitDeviceStatus(string status)
                {
                    Debug.WriteLine("dev status", status);
                    if (status == "ready")
                    {
                        // bytes from F:\node_airtunes2_cider\examples\sample.pcm
                        var bytes = System.IO.File.ReadAllBytes("F:\\node_airtunes2_cider\\examples\\mirrors.raw");
                        airtunes.circularBuffer.Write(bytes);
                    }
                }

                device.emitDeviceStatus += Device_emitDeviceStatus;
                Console.ReadLine();
                Debug.WriteLine("sada");
            }


        

    
}
}