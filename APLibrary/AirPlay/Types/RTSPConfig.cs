using APLibrary.AirPlay.HomeKit;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.Types
{
    public class RTSPConfig
    {
        public int? audioLatency;
        public bool requireEncryption;
        public int? server_port;
        public int? control_port;
        public int? timing_port;
        public Credentials? credentials;

        public RTSPConfig()
        {

        }
    }
}
