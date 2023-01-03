using AirPlayClient;
using APLibrary.AirPlay.HomeKit;
using APLibrary.AirPlay.Types;
using BitConverter;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace APLibrary.AirPlay
{
    public delegate void DeviceStatusEvent(string status);
    public class AirTunesDevice
    {
        private UDPServers udpServers;
        private AudioOut audioOut;
        public string type = "airtunes";
        public string host;
        public int port;
        public string key;
        private int mode;
        private string[] statusflags;
        private bool alacEncoding;
        private string[] txt;
        private string[] features;
        private bool needPassword;
        private bool requireEncryption;
        private bool needPin;
        private bool transient;
        private Socket audioSocket;
        private EndPoint audioSocketEndPoint;
        public string status;
        private bool audioCallbackRunning;
        public event DeviceStatusEvent emitDeviceStatus;
        private const int RTP_HEADER_SIZE = 12;
        public int? audioLatency;
        public int? serverPort;
        public int? controlPort;
        public int? timingPort;
        private Credentials? credentials;
        private RTSPClient rtsp;

        public AirTunesDevice(string host, AudioOut audioOut, AirTunesOptions options, int mode, string[] txt)
        {

            this.udpServers = new UDPServers();
            this.audioOut = audioOut;
            // this.audioOut.emitNeedSync += 

            this.host = host;
            this.port = options.port ?? 5000;
            this.key = this.host + ':' + this.port;
            this.mode = mode; // Homepods with or without passcode
                              // if(options.password != null && legacy == true){
                              // this.mode = 1; // Airport / Shairport legacy passcode mode
                              // this.mode = 2 // MFi mode
                              // }
            this.statusflags = new string[] { };
            this.alacEncoding = options?.alacEncoding ?? true;
            this.txt = txt;
            audioSocketEndPoint = new IPEndPoint(IPAddress.Parse(host), port);

            //get txt starts with et= and check whether it contains 4
            //if yes, then set mode to 2
            var et = txt.Where(x => x.StartsWith("et=")).FirstOrDefault();
            if (et != null && et.Contains("4"))
            {
                this.mode = 2;
            }

            var cn = txt.Where(x => x.StartsWith("cn=")).FirstOrDefault();
            if (cn != null && cn.Contains("0"))
            {
                this.alacEncoding = false;
            }
            //get sf that can starts with sf= or flags=
            var sf = txt.Where(x => x.StartsWith("sf=") || x.StartsWith("flags=")).FirstOrDefault();
            // Get statusflag , convert hexstring (e.g. 0x3343) to binary and split into array
            if (sf != null)
            {             
                var hex = sf.Substring(sf.IndexOf('=') + 1);
                var binary = Convert.ToString(Convert.ToInt32(hex, 16), 2);
                this.statusflags = binary.ToCharArray().Select(x => x.ToString()).ToArray();
            }
            this.needPassword = false;
            this.needPin = false;
            if (this.statusflags != null && this.statusflags.Length > 0)
            {
                bool PasswordRequired = (this.statusflags[this.statusflags.Length - 1 - 7] == "1");
                bool PinRequired = (this.statusflags[this.statusflags.Length - 1 - 3] == "1");
                bool OneTimePairingRequired = (this.statusflags[this.statusflags.Length - 1 - 9] == "1");
                Console.WriteLine("needPss", PasswordRequired, PinRequired, OneTimePairingRequired);
                this.needPassword = (PasswordRequired || PinRequired || OneTimePairingRequired);
                this.needPin = (PinRequired || OneTimePairingRequired);
                Console.WriteLine("needPss", this.needPassword);
            }

            this.transient = false;
            var ft = txt.Where(x => x.StartsWith("features=") || x.StartsWith("ft=")).FirstOrDefault();
            // Get statusflag , convert hexstring (e.g. 0x3343) to binary and split into array
            if (ft != null)
            {
                var hex = ft.Substring(ft.IndexOf('=') + 1);
                // check if hex and has "," then split into 2 array
                var hex_p1 = "";
                var hex_p2 = "";

                hex_p1 = hex.Split(",")[0];
                hex_p2 = hex.Contains(',') ? hex.Split(',')[1] : "";

                var binary1 = Convert.ToString(Convert.ToInt32(hex_p1, 16), 2);
                var binary_set1 = binary1.ToCharArray().Select(x => x.ToString()).ToArray();
                var binary2 = Convert.ToString(Convert.ToInt32(hex_p2, 16), 2);
                var binary_set2 = binary2.ToCharArray().Select(x => x.ToString()).ToArray();
                
                this.features = binary_set1.Concat(binary_set2).ToArray();

                this.transient = (this.features[this.features.Length - 1 - 48] == "1");
            }
         
  
            Console.WriteLine("needPin: " + this.needPin.ToString());
            Console.WriteLine("mode-atv: " + this.mode.ToString());
            Console.WriteLine("alacEncoding: " + this.alacEncoding.ToString());
            Console.WriteLine("AP2: " + options.airplay2.ToString());
            Console.WriteLine("transient: " + this.transient.ToString());

            var APOptions = new AirTunesOptions();
            APOptions.alacEncoding = this.alacEncoding;
            APOptions.mode = this.mode;
            APOptions.needPassword = this.needPassword;
            APOptions.needPin = this.needPin;
            APOptions.debug = options.debug;
            APOptions.airplay2 = options.airplay2;
            APOptions.transient = this.transient;
            APOptions.txt = this.txt;


            this.rtsp = new RTSPClient(options.volume ?? 50, options.password ?? null, audioOut, APOptions);

            //this.audioCallback = null;
            //this.encoder = [];
        }

        public void Start()
        {
            this.audioSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            this.audioSocket.Bind(new IPEndPoint(IPAddress.Any, 0));
            this.udpServers.bind(this.host);
            this.doHandshake();

        }

        private void audioCallback(Packet packet)
        {
            var airTunes = makeAirTunesPacket(packet, requireEncryption, alacEncoding);
            audioSocket.SendTo(airTunes, audioSocketEndPoint);
        }


        void emitRTSPConfig(RTSPConfig setup)
        {
            this.audioLatency = setup.audioLatency;
            this.requireEncryption = setup.requireEncryption;
            this.serverPort = setup.server_port;
            this.controlPort = setup.control_port;
            this.timingPort = setup.timing_port;
        }

        void emitReady()
        {
            this.relayAudio();
        }

        void emitPairSuccess()
        {
            this.emitDeviceStatus?.Invoke("pair_success");
        }

        void emitNeedPassword()
        {
            this.emitDeviceStatus?.Invoke("need_password");
        }

        void emitEnd(string status, string msg)
        {
            this.CleanUp();
            this.emitDeviceStatus?.Invoke(status);

        }
        public void doHandshake()
        {
            this.rtsp.emitEnd += emitEnd;
            this.rtsp.emitNeedPassword += emitNeedPassword;
            this.rtsp.emitPairSuccess += emitPairSuccess;
            this.rtsp.emitReady += emitReady;
            this.rtsp.emitRTSPConfig += emitRTSPConfig;


            this.rtsp.startHandshake(this.udpServers, this.host, this.port.ToString());
        }

        public void relayAudio()
        {
            updateStatus("ready");
            this.audioOut.emitPacket += audioCallback;
            this.audioCallbackRunning = true;
        }

        public void onSyncNeeded(int seq) {
            udpServers.SendControlSync(this, seq);
        }

        public void CleanUp()
        {
            this.audioSocket = null;
            this.status = "stopped";
            updateStatus("stopped");
            // console.log('stop');
            if (this.audioCallbackRunning)
            {
                this.audioOut.emitPacket -= audioCallback;

            }

            this.rtsp.emitEnd -= emitEnd;
            this.rtsp.emitNeedPassword -= emitNeedPassword;
            this.rtsp.emitPairSuccess -= emitPairSuccess;
            this.rtsp.emitReady -= emitReady;
            this.rtsp.emitRTSPConfig -= emitRTSPConfig;

            udpServers.Close();
        }


        public void reportStatus()
        {
            emitDeviceStatus?.Invoke(status);
        }

        public void updateStatus(string status)
        {
            this.status = status;
            emitDeviceStatus?.Invoke(status);
        }

        public void stop(Action cb)
        {
            //this.rtsp.once('end', function() {
            //    if(cb)
            //        cb();
            //});

            this.rtsp.teardown();
        }

        public void setVolume(int volume, Action callback)
        {
            this.rtsp.setVolume(volume, callback);
        }

        public void setTrackInfo(string name, string artist, string album, Action callback)
        {
            this.rtsp.setTrackInfo(name, artist, album, callback);
        }

        public void setArtwork(byte[] art, string contentType, Action callback)
        {

            this.rtsp.setArtwork(art, contentType, callback);
        }

        public void setPasscode(string password)
        {
            this.rtsp.setPasscode(password);
        }

        public void setProgress(int progress, int duration, Action callback)
        {
            this.rtsp.setProgress(progress, duration, callback);
        }

        private byte[] makeAirTunesPacket(Packet packet, bool requireEncryption, bool alacEncoding = true, Credentials? credentials = null)
        {
            // console.log("alacEncoding2",alacEncoding)
            byte[] alac = (alacEncoding || (credentials != null)) ? pcmToALAC(packet.data) : pcmParse(packet.data);
            byte[] airTunes = new byte[alac.Length + RTP_HEADER_SIZE];

            byte[] header = makeRTPHeader(packet);
            if (requireEncryption)
            {
                alac = encryptAES(alac);
            }
            if (credentials != null)
            {
                byte[] pcm = credentials.EncryptAudio(alac, header.Skip(4).Take(8).ToArray(), packet.seq);
                byte[] airplay = new byte[alac.Length + RTP_HEADER_SIZE];
                Array.Copy(header, 0, airplay, 0, header.Length);
                Array.Copy(pcm, 0, airplay, RTP_HEADER_SIZE, pcm.Length);
                return airplay;
                // console.log(alac.length)
            }
            else
            {
                Array.Copy(header, 0, airTunes, 0, header.Length);
                Array.Copy(alac, 0, airTunes, RTP_HEADER_SIZE, alac.Length);
                return airTunes;
            }
        }

        private byte[] pcmToALAC(byte[] pcmData)
        {
            byte[] alacData = new byte[1408 + 8];
            int bsize = 352;
            int frames = 352; // set these to whatever they should be
            byte[] p = new byte[1416]; // p = *out;
            uint[] input = new uint[pcmData.Length / 4];
            int j = 0;
            for (int k = 0; j < pcmData.Length; k += 4)
            {
                var res = pcmData[k];
                res |= (byte)(pcmData[k + 1] << 8);
                res |= (byte)(pcmData[k + 2] << 16);
                res |= (byte)(pcmData[k + 3] << 24);
                input[j++] = res;
            } // uint32_t *in = (uint32_t*) sample;

            int pindex = 0, iindex = 0;

            p[pindex++] = 1 << 5; // 0b100000
            p[pindex++] = 0;
            // 0b1001x, where x = most significant bit of bsize, or basically just { set x if (bsize > 0x80000000) }
            p[pindex++] = (byte)((1 << 4) | (1 << 1) | (byte)((uint)(bsize & 0x80000000) >> 31));
            // bxx--byy = bits xx to yy of bsize
            // so we basically just splitting bsize into the individual byte values and storing them in p
            // we've also shifted everything to the left by one (hence why we need the bit from bsize above)
            p[pindex++] = (byte)((uint)((bsize & 0x7f800000) << 1) >> 24);    // b30--b23
            p[pindex++] = (byte)((uint)((bsize & 0x007f8000) << 1) >> 16);    // b22--b15
            p[pindex++] = (byte)((uint)((bsize & 0x00007f80) << 1) >> 8);    // b14--b7
            p[pindex] = (byte)((uint)(bsize & 0x0000007f) << 1);           // b6--b0
                                                               // and this is why we shifted the bits to the left.
            p[pindex++] |= (byte)((uint)(input[iindex] & 0x00008000) >> 15);   // b7 from in[iindex]

            int count = frames - 1;

            while (count-- > 0)
            {
                var l = input[iindex++]; // just to make it a bit easier to read
                
                // this is weird lmao. everything that we're adding has been shifted left by one.
                // and here, we're soring the lower 16 bits then the higher 16 bits.
                p[pindex++] = (byte)((uint)(l & 0x00007f80) >> 7); // b14--b7
                p[pindex++] = (byte)((byte)((uint)(l & 0x0000007f) << 1) | (byte)((uint)(l & 0x80000000) >> 31)); // b6--b0, b31
                p[pindex++] = (byte)((uint)(l & 0x7f800000) >> 23); // b30--b23
                p[pindex++] = (byte)((byte)((uint)(l & 0x007f0000) >> 15) | ((input[iindex] & 0x00008000) >> 15));// b16--b15, b7 from in[pindex]
            }

            // last sample
            uint i = input[iindex];
            p[pindex++] = (byte)((uint)(i & 0x00007f80) >> 7); // b14--b7
            p[pindex++] = (byte)(((i & 0x0000007f) << 1) | ((byte)((uint)i & 0x80000000) >> 31)); // b6--b0, b31
            p[pindex++] = (byte)((uint)(i & 0x7f800000) >> 23); // b30--b23
            p[pindex++] = (byte)((uint)(i & 0x007f0000) >> 15); // b16--b15, 0 as last bit because we have no more data after this

            // when we've read all we can from in, we need to fill the remaining space in p with 0's
            count = (bsize - frames) * 4;
            while (count-- > 0) p[pindex++] = 0;

            // frame footer ??
            p[pindex - 1] |= 1;
            p[pindex++] = (int)((uint)7 >> 1) << 6;

            // const size = pindex;

            int alacSize = pindex; // should be right
            alacData = p;
            return alacData.Skip(0).Take(alacSize).ToArray();

        }

        private byte[] pcmParse(byte[] pcmData)
        {
            byte[] dst = new byte[352 * 4];
            byte[] src = pcmData;

            int a = 0;
            int b = 0;
            int size;
            for (size = 0; size < 352; size++)
            {
                dst[a++] = src[b + 1];
                dst[a++] = src[b++];
                b++;

                dst[a++] = src[b + 1];
                dst[a++] = src[b++];
                b++;
            }
            size *= 4;
            return dst;
        }

        private byte[] makeRTPHeader(Packet packet)
        {
            var header = new byte[RTP_HEADER_SIZE];

            if (packet.seq == 0)
            {
                Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80e0), 0, header, 0, 2);
            }
            else
            {
                Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x8060), 0, header, 0, 2);
            }

            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)(packet.seq % 65536)), 0, header, 2, 2);

            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)packet.timestamp), 0, header, 4, 4);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)334088158), 0, header, 8, 4);

            return header;
        }

        private byte[] encryptAES(byte[] alacData)
        {
              byte[] result = new byte[0];
              byte[] isv = new byte[] { 0x78, 0xf4, 0x41, 0x2c, 0x8d, 0x17, 0x37, 0x90, 0x2b, 0x15, 0xa6, 0xb3, 0xee, 0x77, 0x0d, 0x67 };
              byte[] aes_key = new byte[] { 0x14, 0x49, 0x7d, 0xcc, 0x98, 0xe1, 0x37, 0xa8, 0x55, 0xc1, 0x45, 0x5a, 0x6b, 0xc0, 0xc9, 0x79 };
              int remainder = alacData.Length % 16;
              Aes aes = Aes.Create();
              aes.Key = aes_key;
              aes.IV = isv;
              aes.BlockSize = 128;
              aes.Mode = CipherMode.CBC;
              aes.Padding = PaddingMode.None;
              int end_of_encoded_data = alacData.Length - remainder;  
              int l = end_of_encoded_data - 16;
              ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            for (int i = 0; i <= l; i += 16)
              {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                    {
                            cs.Write(alacData, i, 16);
                    }

                    byte[] chunk = ms.ToArray();
                    result = result.Concat(chunk).ToArray();
                }
                
	          }
              return result.Concat(alacData.Skip(remainder).ToArray()).ToArray();
        }

    }
}
