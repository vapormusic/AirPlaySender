using AirPlayClient;
using APLibrary.AirPlay.HomeKit;
using APLibrary.AirPlay.Types;
using APLibrary.AirPlay.Utils;
using BitConverter;
using Claunia.PropertyList;
using Microsoft.VisualBasic;
using Newtonsoft.Json.Linq;
using Rebex.Security.Cryptography;
using SecureRemotePassword;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using static System.Net.WebRequestMethods;

namespace APLibrary.AirPlay
{
    public delegate void EmitEndEvent(string status,string msg);
    public delegate void NeedPassword();
    public class RTSPClient
    {
        //TODO: write rtsp.js to c#
        private static string user_agent = "iTunes/11.3.1 (Windows; Microsoft Windows 10 x64(Build 19044); x64) (dt:2)";
        private AudioOut audioOut;
        private int status;
        private TcpClient? socket;
        private int cseq;
        private string? announceId;
        private string? activeRemote;
        private string? dacpId;
        private string? session;
        private CancellationTokenSource? timeout;
        private int? volume;
        private int? progress;
        private int? duration;
        private int? starttime;
        private string password;
        private bool passwordTried;
        private bool requireEncryption;
        private Dictionary<string, string>? trackInfo;
        private byte[] artwork;
        private string artworkContentType;
        private Action callback;
        private int? controlPort;
        private int? timingPort;
        private int? timingDestPort;  
        private int? eventPort;
        private System.Timers.Timer? heartBeat;
        private Dictionary<string,string>? pair_verify_1_verifier;
        private byte[] pair_verify_1_signature;
        private byte[] code_digest;
        private string authSecret;
        private int mode;
        private string[] dnstxt;
        private bool alacEncoding;
        private bool needPassword;
        private bool airplay2;
        private bool needPin;
        private bool debug;
        private bool transient;
        private bool borkedshp;
        private byte[] privateKey;
        private SrpClient? srp;
        private string I = "366B4165DD64AD3A";
        private string P;
        private string s;
        private string B;
        private string A;
        private string a;
        private byte[] Al;
        private string M1;
        private string epk;
        private string authTag;
        private byte[] _atv_salt;
        private byte[] _atv_pub_key;
        private byte[] _hap_genkey;
        private byte[] _hap_encrypteddata;
        private string? pairingId;
        private byte[] K;
        private byte[] seed ;
        private Credentials credentials;
        private byte[] event_credentials;
        private Dictionary<string, byte[]>? verifier_hap_1;
        private byte[] verifyPrivate;
        private byte[] verifyPublic;
        private byte[] encryptionKey;
        private bool encryptedChannel;
        private string hostip;
        private string homekitver;
        private NetworkStream nsctrl;
        private StreamReader srctrl;
        public event EmitEndEvent emitEnd;
        public event NeedPassword emitNeedPassword;
        private const int INFO = -1,
        OPTIONS = 0,
        ANNOUNCE = 1,
        SETUP = 2,
        RECORD = 3,
        SETVOLUME = 4,
        PLAYING = 5,
        TEARDOWN = 6,
        CLOSED = 7,
        SETDAAP = 8,
        SETART = 9,
        PAIR_VERIFY_1 = 10,
        PAIR_VERIFY_2 = 11,
        OPTIONS2 = 12,
        AUTH_SETUP = 13,
        PAIR_PIN_START = 14,
        PAIR_PIN_SETUP_1 = 15,
        PAIR_PIN_SETUP_2 = 16,
        PAIR_PIN_SETUP_3 = 17,
        PAIR_SETUP_1 = 18,
        PAIR_SETUP_2 = 19,
        PAIR_SETUP_3 = 20,
        PAIR_VERIFY_HAP_1 = 21,
        PAIR_VERIFY_HAP_2 = 22,
        SETUP_AP2_1 = 23,
        SETUP_AP2_2 = 24,
        SETPEERS = 25,
        FLUSH = 26,
        GETVOLUME = 27,
        SETPROGRESS = 28;

        public RTSPClient(int volume, string password, AudioOut audioOut, AirTunesOptions options)
        {
            this.audioOut = audioOut;
            this.status = PAIR_VERIFY_1;
            this.socket = null;
            this.cseq = 0;
            this.announceId = null;
            this.activeRemote = Utils.Utils.randomInt(9).ToString().ToUpper();
            this.dacpId = Utils.Utils.randomHex(8).ToUpper();
            this.session = null;
            this.timeout = null;
            this.volume = volume;
            this.progress = 0;
            this.duration = 0;
            this.starttime = 0;
            this.password = password;
            this.passwordTried = false;
            this.requireEncryption = false;
            this.trackInfo = null;
            this.artwork = null;
            this.artworkContentType = null;
            this.callback = null;
            this.controlPort = null;
            this.timingPort = null;
            this.timingDestPort = null;
            this.eventPort = null;
            this.heartBeat = null;
            this.pair_verify_1_verifier = null;
            this.pair_verify_1_signature = null;
            this.code_digest = null;
            this.authSecret = null;
            this.mode = options?.mode ?? 0;
            this.dnstxt = options?.txt ?? new string[0];
            this.alacEncoding = options?.alacEncoding ?? true;
            this.needPassword = options?.needPassword ?? false;
            this.airplay2 = options?.airplay2 ?? false;
            this.needPin = options?.needPin ?? false;
            this.debug = options?.debug ?? false;
            this.transient = options?.transient ?? false;
            this.borkedshp = options?.borkedshp ?? false;
            this.privateKey = null;
            this.srp = null;
            this.I = "366B4165DD64AD3A";
            this.P = null;
            this.s = null;
            this.B = null;
            this.a = null;
            this.A = null;
            this.M1 = null;
            this.epk = null;
            this.authTag = null;
            this._atv_salt = null;
            this._atv_pub_key = null;
            this._hap_genkey = null;
            this._hap_encrypteddata = null;
            this.pairingId = null;
            this.seed = null;
            this.credentials = null;
            this.event_credentials = null;
            this.verifier_hap_1 = null;
            this.encryptionKey = null;
            this.encryptedChannel = false;
            this.hostip = null;
            this.homekitver = (this.transient == true) ? "4" : "3";
        }

        private CancellationTokenSource SetTimeout(Action action, int millis)
        {

            var cts = new CancellationTokenSource();
            var ct = cts.Token;
            _ = Task.Run(() => {
                Thread.Sleep(millis);
                if (!ct.IsCancellationRequested)
                    action();
            }, ct);

            return cts;
        }

        public void ClearTimeout(CancellationTokenSource cts)
        {
            cts.Cancel();
        }

        public void startHandshake(UDPServers udpServers, string host, string port)
        {
            //var self = this;
            // this.startTimeout();
            this.controlPort = ((IPEndPoint)udpServers.controlEndPoint).Port;
            this.timingPort = ((IPEndPoint)udpServers.timingEndPoint).Port;
            this.hostip = host;

            this.socket = new TcpClient();
            this.socket.ReceiveTimeout = 400000000;
            this.socket.SendTimeout = 400000000;
            this.socket.ConnectAsync(host, int.Parse(port)).ContinueWith(task => {

                nsctrl = this.socket.GetStream();
                srctrl = new StreamReader(nsctrl);
                // this.clearTimeout();

                if (this.needPassword)
                {
                    this.status = PAIR_PIN_START;
                    this.sendNextRequest();
                    this.startHeartBeat();
                }
                else
                {
                    if (this.mode != 2)
                    {
                        if (this.debug) Console.WriteLine("AUTH_SETUP", "nah");
                        this.status = OPTIONS;
                        this.sendNextRequest();
                        this.startHeartBeat();
                    }
                    else
                    {
                        this.status = AUTH_SETUP;
                        if (this.debug) Console.WriteLine("AUTH_SETUP", "yah");
                        this.sendNextRequest();
                        this.startHeartBeat();
                    }


                }
            });

        }

        public void ExecRequest(byte[] input ,bool GetResponse){
            if (this.encryptedChannel && this.credentials != null)
            {
                input = this.credentials.encrypt(input);
            }
            nsctrl.Write(input, 0, input.Length);

            if (!GetResponse)
                return;

            byte[] res = null;
            int lastRead = 0;

            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buffer = new byte[4096];
                do
                {
                    lastRead = nsctrl.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, lastRead);
                } while (lastRead > 0);

                res = ms.ToArray();
            }
            if (this.encryptedChannel && this.credentials != null)
            {
                res = this.credentials.decrypt(res);
            }
            processData(res);
        }

        //private void startTimeout()
        //{
        //    var self = this;
        //    this.timeout = setTimeout(function() {
        //        if (self.debug) console.log("timeout");
        //        self.cleanup("timeout");
        //    }, config.rtsp_timeout);
        //};

        //private void clearTimeout()
        //{
        //    if (this.timeout !== null)
        //    {
        //        clearTimeout(this.timeout);
        //        this.timeout = null;
        //    }
        //};

        public void teardown()
        {
            if (this.status == CLOSED)
            {
                emitEnd?.Invoke("stopped", "");
                return;
            }

            this.status = TEARDOWN;
            this.sendNextRequest();
        }

        public void setVolume(int volume, Action callback)
        {
            if (this.status != PLAYING)
                return;

            this.volume = volume;
            this.callback = callback;
            this.status = SETVOLUME;
            this.sendNextRequest();
        }

        public void setProgress(int progress, int duration, Action callback)
        {
            if (this.status != PLAYING)
                return;
            this.progress = progress;
            this.duration = duration;
            this.callback = callback;
            this.status = SETPROGRESS;
            this.sendNextRequest();
        }

        public void setPasscode(string passcode)
        {
            this.password = passcode;
            this.status = this.airplay2 ? PAIR_SETUP_1 : PAIR_PIN_SETUP_1;
            this.sendNextRequest();
        }

        public void startHeartBeat()
        {
            if (15000 > 0)
            {
                void sendHB() {
                    this.sendHeartBeat();
                }
                this.heartBeat = Interval.Set(sendHB, 15000);
            }
        }

        private void sendHeartBeat() 
        {
            if (this.status != PLAYING)
                return;

            this.status = OPTIONS;
            this.sendNextRequest();
        }

        public void setTrackInfo(string name, string artist, string album, Action callback)
        {
            if (this.status != PLAYING)
                return;
            string? name1 = null;
            this.trackInfo?.TryGetValue("name", out name1);
            string? artist1 = null;
            this.trackInfo?.TryGetValue("artist", out artist1);
            string? album1 = null;
            this.trackInfo?.TryGetValue("album", out album1);
            if (name != name1 || artist != artist1 || album != album1)
            {
                this.starttime = this.audioOut.lastSeq * 352 + 2 * 44100;
            }
            this.trackInfo = new Dictionary<string, string>();
            this.trackInfo.Add("name", name);
            this.trackInfo.Add("artist", artist);
            this.trackInfo.Add("album", album);
            this.status = SETDAAP;
            this.callback = callback;
            this.sendNextRequest();
        }

        public void setArtwork(byte[] art, string contentType, Action callback)
        {
            if (this.status != PLAYING)
                return;

            //if (typeof contentType == "function")
            //{
            //    callback = contentType;
            //    contentType = null;
            //}

            //if (typeof art == "string")
            //{
            //    var self = this;
            //    if (contentType === null)
            //    {
            //        var ext = art.slice(-4);
            //        if (ext == ".jpg" || ext == "jpeg")
            //        {
            //            contentType = "image/jpeg";
            //        }
            //        else if (ext == ".png")
            //        {
            //            contentType = "image/png";
            //        }
            //        else if (ext == ".gif")
            //        {
            //            contentType = "image/gif";
            //        }
            //        else
            //        {
            //            return self.cleanup("unknown_art_file_ext");
            //        }
            //    }
            //    return fs.readFile(art, function(err, data) {
            //        if (err !== null)
            //        {
            //            return self.cleanup("invalid_art_file");
            //        }
            //        self.setArtwork(data, contentType, callback);
            //    });
            //}

            //if (contentType === null)
            //    return this.cleanup("no_art_content_type");

            this.artworkContentType = contentType;
            this.artwork = art;
            this.status = SETART;
            this.callback = callback;
            this.sendNextRequest();
        }
        
        public int nextCSeq()
        {
            this.cseq += 1;

            return this.cseq;
        }

        public void cleanup(string type, string msg = "")
        {
            emitEnd?.Invoke(type, msg);
            this.status = CLOSED;
            this.trackInfo = null;
            this.artwork = null;
            this.artworkContentType = null;
            this.callback = null;
            this.srp = null;
            this.P = null;
            this.s = null;
            this.B = null;
            this.a = null;
            this.A = null;
            this.M1 = null;
            this.epk = null;
            this.authTag = null;
            this._hap_genkey = null;
            this._hap_encrypteddata = null;
            this.seed = null;
            this.credentials = null;
            this.password = null;
            //this.removeAllListeners();

            if (this.timeout != null)
            {
                ClearTimeout(this.timeout);
                this.timeout = null;
            }
            
            if (this.heartBeat != null)
            {
                Interval.Stop(this.heartBeat);
                this.heartBeat = null;
            }

            if (this.socket != null)
            {
                this.socket.Close();
                this.socket = null;
            }
        }
        
        public byte[] makeHead(string method, string uri, DI? di = null, bool clear = false)
        {
            string head = method + " " + uri + " RTSP/1.0" + "\r\n";
            if (!clear)
            {
                head += "CSeq: " + this.nextCSeq() + "\r\n" +
                "User-Agent: " + (this.airplay2 ? "AirPlay/409.16" : user_agent) + "\r\n" +
                "DACP-ID: " + this.dacpId + "\r\n" +
                ((this.session != null) ? "Session: " + this.session + "\r\n" : "") +
                "Active-Remote: " + this.activeRemote + "\r\n";
                head += "Client-Instance: " + this.dacpId + "\r\n";
            };

            if (di != null)
            {
                var ha1 = Utils.Utils.CreateMD5(di.username + ":" + di.realm + ":" + di.password);
                var ha2 = Utils.Utils.CreateMD5(method + ":" + uri);
                var diResponse = Utils.Utils.CreateMD5(ha1 + ":" + di.nonce + ":" + ha2);

                head += "Authorization: Digest " +
                  "username=\"" + di.username + "\", " +
                  "realm=\"" + di.realm + "\", " +
                  "nonce=\"" + di.nonce + "\", " +
                  "uri=\"" + uri + "\", " +
                  "response=\"" + diResponse + "\"\r\n";
            }

            return System.Text.Encoding.Unicode.GetBytes(head);
        }

        public byte[] makeHeadWithURL (string method, DI digestInfo)
        {
            return this.makeHead(method, "rtsp://" + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.ToString() + "/" + this.announceId, digestInfo);
        }

        public string makeRtpInfo()
        {
            var nextSeq = (this.audioOut.lastSeq + 1);
            var rtpSyncTime = nextSeq * 352 + 2 * 44100;
            return "RTP-Info: seq=" + nextSeq.ToString() + ";rtptime=" + rtpSyncTime.ToString() + "\r\n";
        }

        public void sendNextRequest(int? force_mode = null, DI? di = null)
        {
            if (force_mode != null)
            {
                this.status = force_mode.Value;
            }

            byte[] request = new byte[0];
            bool getResponse = true;
            string u = "";

            switch (this.status)
            {
                case PAIR_PIN_START:
                    this.I = "366B4165DD64AD3A";
                    this.P = null;
                    this.s = null;
                    this.B = null;
                    this.a = null;
                    this.A = null;
                    this.M1 = null;
                    this.epk = null;
                    this.authTag = null;
                    this._atv_salt = null;
                    this._atv_pub_key = null;
                    this._hap_encrypteddata = null;
                    this.seed = null;
                    this.pairingId = Guid.NewGuid().ToString();
                    this.credentials = null;
                    this.verifier_hap_1 = null;
                    this.encryptionKey = null;
                    
                    if (this.needPin || this.airplay2)
                    {
                        request = request.Concat(this.makeHead("POST", "/pair-pin-start", null, true)).ToArray();
                        if (this.airplay2)
                        {

                            u += "User-Agent: AirPlay/409.16\r\n";
                            u += "Connection: keep-alive\r\n";
                            u += "CSeq: " + "0" + "\r\n";
                            
                        }
                        u += "Content-Length:" + 0 + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    } else
                    {
                        emitNeedPassword?.Invoke();
                        this.status = this.airplay2 ? INFO : PAIR_PIN_SETUP_1;
                    }
                    break;
                case PAIR_PIN_SETUP_1:
                    request = request.Concat(this.makeHead("POST", "/pair-setup-pin", null, true)).ToArray();
                    u += "Content-Type: application/x-apple-binary-plist\r\n";
                    
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("user", "366B4165DD64AD3A");
                        dict.Add("method", "pin");
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    
                    break;
                case PAIR_PIN_SETUP_2:
                    request = request.Concat(this.makeHead("POST", "/pair-setup-pin", null, true)).ToArray();
                    u += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("pk", new NSData(this.A));
                        dict.Add("proof", new NSData(this.M1));
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case PAIR_PIN_SETUP_3:
                    request = request.Concat(this.makeHead("POST", "/pair-setup-pin", null, true)).ToArray();
                    u += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("epk", new NSData(this.epk));
                        dict.Add("authTag", new NSData(this.authTag));
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case PAIR_VERIFY_1:
                    request = request.Concat(this.makeHead("POST", "/pair-verify", null, true)).ToArray();
                    u += "Content-Type: application/octet-stream\r\n";
                    this.pair_verify_1_verifier = LegacyATVVerifier.verifier(this.authSecret);
                    u += "Content-Length:" + this.pair_verify_1_verifier["verifierBody"].Length + "\r\n\r\n";

                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(Convert.FromHexString(this.pair_verify_1_verifier["verifierBody"])).ToArray();
                    break;
                case PAIR_VERIFY_2:
                    request = request.Concat(this.makeHead("POST", "/pair-verify", null, true)).ToArray();
                    u += "Content-Type: application/octet-stream\r\n";
                    u += "Content-Length:" + this.pair_verify_1_signature.Length + "\r\n\r\n";
                    
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(this.pair_verify_1_signature).ToArray();
                    break;
                case PAIR_SETUP_1:
                    request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    if (this.transient == true)
                    {
                        Dictionary<byte, byte[]> dic1 = new Dictionary<byte, byte[]>();
                        dic1.Add(TlvTag.Sequence, EndianBitConverter.LittleEndian.GetBytes(0x01));
                        dic1.Add(TlvTag.PairingMethod, EndianBitConverter.LittleEndian.GetBytes(0x00));
                        dic1.Add(TlvTag.Flags, EndianBitConverter.LittleEndian.GetBytes(0x00000010));
                        byte[] ps1x = Tlv.Encode(dic1);

                        u += "Content-Length: " + ps1x.Length + "\r\n";
                        u += "Content-Type: application/octet-stream" + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(ps1x).ToArray();
                    }
                    else
                    {
                        Dictionary<byte, byte[]> dic2 = new Dictionary<byte, byte[]>();
                        dic2.Add(TlvTag.PairingMethod, EndianBitConverter.LittleEndian.GetBytes(0x00));
                        dic2.Add(TlvTag.Sequence, EndianBitConverter.LittleEndian.GetBytes(0x01));
                        dic2.Add(TlvTag.Flags, EndianBitConverter.LittleEndian.GetBytes(0x00000010));
                        byte[] ps2x = Tlv.Encode(dic2);
                        u += "Content-Length: " + "6" + "\r\n";
                        u += "Content-Type: application/octet-stream" + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(ps2x).ToArray();
                    }
                    break;
                case PAIR_SETUP_2:
                    request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    u += "Content-Type: application/octet-stream\r\n";
                    var dic = new Dictionary<byte, byte[]>();
                    dic.Add(TlvTag.Sequence, EndianBitConverter.LittleEndian.GetBytes(0x03));
                    dic.Add(TlvTag.PublicKey, Convert.FromHexString(this.A));
                    dic.Add(TlvTag.Proof, Convert.FromHexString(this.M1));
                    var ps2 = Tlv.Encode(dic);
                    u += "Content-Length: " + ps2.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(ps2).ToArray();
                    break;
                case PAIR_SETUP_3:
                    request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    u += "Content-Type: application/octet-stream\r\n";
                    this.K = Convert.FromHexString(this.srp.DeriveSession(Convert.ToHexString(this._hap_genkey), Convert.ToHexString(this._atv_pub_key), Convert.ToHexString(this._atv_salt), "Pair-Setup", this.password).Key);
                    this.seed = new byte[32];
                    RandomNumberGenerator rng = RandomNumberGenerator.Create();
                    rng.GetBytes(this.seed);
                    var ed = new Ed25519();
                    ed.FromSeed(this.seed);
                    byte[] publicKey = ed.GetPublicKey();
                    byte[] deviceHash = Encryption.HKDF(
                        Encoding.ASCII.GetBytes("Pair-Setup-Controller-Sign-Salt"),
                        this.K,
                        Encoding.ASCII.GetBytes("Pair-Setup-Controller-Sign-Info"),
                        32
                    );
                    byte[] deviceInfo = deviceHash.Concat(Encoding.ASCII.GetBytes(this.pairingId)).Concat(publicKey).ToArray();
                    byte[] deviceSignature = ed.SignMessage(deviceInfo);
                    // let deviceSignature = nacl.sign(deviceInfo, privateKey)
                    this.encryptionKey = Encryption.HKDF(
                        Encoding.ASCII.GetBytes("Pair-Setup-Encrypt-Salt"),
                        this.K,
                        Encoding.ASCII.GetBytes("Pair-Setup-Encrypt-Info"),
                        32
                    );
                    Dictionary<byte, byte[]> dic3a = new Dictionary<byte, byte[]>();
                    dic3a.Add(TlvTag.Username, Encoding.ASCII.GetBytes(this.pairingId));
                    dic3a.Add(TlvTag.PublicKey, publicKey);
                    dic3a.Add(TlvTag.Signature, deviceSignature);
                    byte[] ps3xa = Tlv.Encode(dic3a);
                    (byte[] encryptedTLV, byte[] encryptedTLVhmac) = Encryption.EncryptAndSeal(ps3xa, null, Encoding.ASCII.GetBytes("PS-Msg05"), this.encryptionKey);
                    Dictionary<byte, byte[]> dic3b = new Dictionary<byte, byte[]>();
                    dic3b.Add(TlvTag.Sequence, EndianBitConverter.LittleEndian.GetBytes(0x05));
                    dic3b.Add(TlvTag.EncryptedData, encryptedTLV.Concat(encryptedTLVhmac).ToArray());
                    byte[] ps3xb = Tlv.Encode(dic3b);
                    u += "Content-Length: " + ps3xb.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(ps3xb).ToArray();
                    break;
                case PAIR_VERIFY_HAP_1:
                    request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    u += "Content-Type: application/octet-stream\r\n";
                    var curve = new Curve25519();
                    curve.FromPrivateKey(this.seed);
                    this.verifyPrivate = curve.GetPrivateKey();
                    this.verifyPublic = curve.GetPrivateKey();
                    Dictionary<byte, byte[]> dic4 = new Dictionary<byte, byte[]>();
                    dic4.Add(TlvTag.Sequence, EndianBitConverter.LittleEndian.GetBytes(0x01));
                    dic4.Add(TlvTag.PublicKey, this.verifyPublic);
                    byte[] ps4 = Tlv.Encode(dic4);
                    u += "Content-Length: " + ps4.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(ps4).ToArray();
                    break;
                case PAIR_VERIFY_HAP_2:
                    request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    u += "Content-Type: application/octet-stream\r\n";
                    //byte[] identifier = Tlv.Decode(this.verifier_hap_1["pairingData"])[TlvTag.Username];
                    //byte[] signature = Tlv.Decode(this.verifier_hap_1["pairingData"])[TlvTag.Signature];
                    byte[] material = this.verifyPublic.Concat(Encoding.ASCII.GetBytes(this.credentials.pairingId)).Concat(this.verifier_hap_1["sessionPublicKey"]).ToArray();
                    var ed2 = new Ed25519();
                    ed2.FromPrivateKey(this.privateKey);
                    byte[] signed = ed2.SignMessage(material);
                    Dictionary<byte, byte[]> dic5a = new Dictionary<byte, byte[]>();
                    dic5a.Add(TlvTag.Username, Encoding.ASCII.GetBytes(this.pairingId));
                    dic5a.Add(TlvTag.Signature, signed);
                    byte[] ps5a = Tlv.Encode(dic5a);
                    (byte[] encryptedTLV1, byte[] encryptedTLV1Hmac) = Encryption.EncryptAndSeal(ps5a, null, Encoding.ASCII.GetBytes("PV-Msg03"), this.verifier_hap_1["encryptionKey"]);
                    Dictionary<byte, byte[]> dic5b = new Dictionary<byte, byte[]>();
                    dic5b.Add(TlvTag.Sequence, EndianBitConverter.LittleEndian.GetBytes(0x03));
                    dic5b.Add(TlvTag.EncryptedData, encryptedTLV1.Concat(encryptedTLV1Hmac).ToArray());
                    byte[] ps5b = Tlv.Encode(dic5b);
                    u += "Content-Length: " + ps5b.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(ps5b).ToArray();
                    break;
                case AUTH_SETUP:
                    request = request.Concat(this.makeHead("POST", "/auth-setup", di)).ToArray();
                    u += "Content-Length:" + "33" + "\r\n\r\n";
                    byte[] auth_fakekey_buf = new byte[] {0x01, // unencrypted
                            0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, // static Curve 25519 key
                            0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82, 0x07,
                            0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b,
                            0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d, 0x4e};
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(auth_fakekey_buf).ToArray();
                    break;
                case OPTIONS:
                    request = request.Concat(this.makeHead("OPTIONS", "*", di)).ToArray();
                    if (this.airplay2)
                    {
                        u += "User-Agent: AirPlay/409.16\r\n";
                        u += "Connection: keep-alive\r\n";
                    }
                    u += "Apple-Challenge: SdX9kFJVxgKVMFof/Znj4Q\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case OPTIONS2:
                    request = request.Concat(this.makeHead("OPTIONS", "*", di)).ToArray();
                    u += this.code_digest;
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case ANNOUNCE:
                    if (this.announceId == null)
                    {
                        this.announceId = Utils.Utils.randomInt(10).ToString();
                    }

                    string body =
                      "v=0\r\n" +
                      "o=iTunes " + this.announceId + " 0 IN IP4 " + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.ToString() + "\r\n" +
                      "s=iTunes\r\n" +
                      "c=IN IP4 " + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.ToString() + "\r\n" +
                      "t=0 0\r\n" +
                      "m=audio 0 RTP/AVP 96\r\n";
                    if (!this.alacEncoding)
                    {
                        body = body + "a=rtpmap:96 L16/44100/2\r\n" +
                        "a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n";
                    } else {
                        body = body + "a=rtpmap:96 AppleLossless\r\n" +
                        "a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n";
                     }
;
                    if (this.requireEncryption)
                    {
                        body +=
                          "a=rsaaeskey:" + "VjVbxWcmYgbBbhwBNlCh3K0CMNtWoB844BuiHGUJT51zQS7SDpMnlbBIobsKbfEJ3SCgWHRXjYWf7VQWRYtEcfx7ejA8xDIk5PSBYTvXP5dU2QoGrSBv0leDS6uxlEWuxBq3lIxCxpWO2YswHYKJBt06Uz9P2Fq2hDUwl3qOQ8oXb0OateTKtfXEwHJMprkhsJsGDrIc5W5NJFMAo6zCiM9bGSDeH2nvTlyW6bfI/Q0v0cDGUNeY3ut6fsoafRkfpCwYId+bg3diJh+uzw5htHDyZ2sN+BFYHzEfo8iv4KDxzeya9llqg6fRNQ8d5YjpvTnoeEQ9ye9ivjkBjcAfVw" + "\r\n" +
                          "a=aesiv:" + "ePRBLI0XN5ArFaaz7ncNZw" + "\r\n";
                    }

                    request = request.Concat(this.makeHeadWithURL("ANNOUNCE", di)).ToArray(); 
                    u +=
                      "Content-Type: application/sdp\r\n" +
                      "Content-Length: " + body.Length + "\r\n\r\n";

                    u += body;
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    //console.log(request);
                    break;
                case SETUP:
                    request = request.Concat(this.makeHeadWithURL("SETUP", di)).ToArray();
                    u += "Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;" +
                      "control_port=" + this.controlPort + ";" +
                      "timing_port=" + this.timingPort + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    //console.log(request);
                    break;
                case INFO:
                    request = request.Concat(this.makeHead("GET", "/info", di, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case SETUP_AP2_1:
                    if (this.announceId == null)
                    {
                        this.announceId = Utils.Utils.randomInt(10).ToString();
                    }
                    request = request.Concat(this.makeHeadWithURL("SETUP", di)).ToArray();
                    u += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary dict = new NSDictionary();
                        dict.Add("deviceID", "2C:61:F3:B6:64:C1");
                        dict.Add("sessionUUID", "8EB266BA-B741-40C5-8213-4B7A38DF8773");
                        dict.Add("timingPort", this.timingPort);
                        dict.Add("timingProtocol", "NTP");
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case SETPEERS:
                    request = request.Concat(this.makeHeadWithURL("SETPEERS", di)).ToArray();
                    u += "Content-Type: /peer-list-changed\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSArray dict = new NSArray(2);
                        dict.SetValue(0, this.hostip);
                        dict.SetValue(1, ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.ToString());
                        bplist.Write(dict);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case FLUSH:
                    request = request.Concat(this.makeHeadWithURL("FLUSH", di)).ToArray();
                    u += this.makeRtpInfo() + "\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case SETUP_AP2_2:
                    if (this.announceId == null)
                    {
                        this.announceId = Utils.Utils.randomInt(10).ToString();
                    }
                    request = request.Concat(this.makeHeadWithURL("SETUP", di)).ToArray();
                    u += "Content-Type: application/x-apple-binary-plist\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSDictionary streams = new NSDictionary();
                        NSArray array = new NSArray(1);
                        NSDictionary stream = new NSDictionary();
                        stream.Add("audioFormat", 262144); // PCM/44100/16/2
                        stream.Add("audioMode", "default");
                        stream.Add("controlPort", this.controlPort);
                        stream.Add("ct", 2);
                        stream.Add("isMedia", true);
                        stream.Add("latencyMax", 88200);
                        stream.Add("latencyMin", 11025);
                        stream.Add("shk", this.credentials.writeKey);
                        stream.Add("spf", 352);
                        stream.Add("sr", 44100);
                        stream.Add("type", 0x60);
                        stream.Add("supportsDynamicStreamID", false);
                        stream.Add("streamConnectionID", this.announceId);

                        array.SetValue(0, stream);
                        streams.Add("streams", array);
                        bplist.Write(streams);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";}
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case RECORD:
                    if (this.airplay2 != null && this.credentials != null) {
                        var nextSeq = this.audioOut.lastSeq + 10;
                        var rtpSyncTime = nextSeq* 352 + 2* 44100;
                        request = request.Concat(this.makeHead("RECORD", "rtsp://" + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.ToString() + "/" + this.announceId, di, true)).ToArray();
                        u += "CSeq: "+ ++this.cseq+ "\r\n";
                        u += "User-Agent: AirPlay/409.16" + "\r\n";
                        u += "Client-Instance: " + this.dacpId + "\r\n";
                        u += "DACP-ID: " + this.dacpId + "\r\n";
                        u += "Active-Remote: " + this.activeRemote+ "\r\n";
                        u += "X-Apple-ProtocolVersion: 1\r\n";
                        u += "Range: npt=0-\r\n";
                        u += this.makeRtpInfo()+ "\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    } else {
                        request = request.Concat(this.makeHeadWithURL("RECORD", di)).ToArray();
                        u += "Range: npt=0-\r\n";
                        u += this.makeRtpInfo()+ "\r\n";
                        request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    }
                    break;
                case GETVOLUME:
                    string body1 = "volume\r\n";
                    request = request.Concat(this.makeHeadWithURL("GET_PARAMETER", di)).ToArray();
                    u +=
                       "Content-Type: text/parameters\r\n" +
                       "Content-Length: " + body1.Length + "\r\n\r\n";
                    u += body1;
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case SETVOLUME:
                    var attenuation =
                              this.volume == 0.0 ?
                              -144.0 :
                              (-30.0)*(100 - this.volume)/100.0;

                    string body2 = "volume: " + attenuation.ToString() + "\r\n";
                    
                    request = request.Concat(this.makeHeadWithURL("GET_PARAMETER", di)).ToArray();
                    u +=
                              "Content-Type: text/parameters\r\n" +
                              "Content-Length: " + body2.Length + "\r\n\r\n";
                    
                    u += body2;
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case SETPROGRESS:
                    string hms(int seconds) {
                         return TimeSpan.FromSeconds(seconds).ToString(@"hh\:mm\:ss");
                    }
                    int position = (int)(this.starttime + (this.progress) * (int)(Math.Floor((2*44100)/(352/125)/0.71)));
                    int duration = (int)(this.starttime + (this.duration) * (int)(Math.Floor((2*44100)/(352/125)/0.71)));
                    string body3 = "progress: " + this.starttime.ToString() +"/"+ position.ToString() + "/"+ duration.ToString() + "\r\n";
                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u +=
                              "Content-Type: text/parameters\r\n" +
                              "Content-Length: " + body3.Length + "\r\n\r\n";
                    u += body3;
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray();
                    break;
                case SETDAAP:
                    bool daapenc = true;
                            //daapenc = true
                    byte[] name = this.daapEncode("minm", this.trackInfo["name"],daapenc);
                    byte[] artist = this.daapEncode("asar", this.trackInfo["artist"], daapenc);
                    byte[] album = this.daapEncode("asal", this.trackInfo["album"], daapenc);
                    byte[][] trackargs = new byte[][] { name, artist, album };
                    
                    byte[] daapInfo = this.daapEncodeList("mlit", daapenc, trackargs);

                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u += this.makeRtpInfo();
                    u +=
                    "Content-Type: application/x-dmap-tagged\r\n" +
                    "Content-Length: " + daapInfo.Length + "\r\n\r\n";

                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(daapInfo).ToArray();
                    break;
                case SETART:
                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u += this.makeRtpInfo();
                    u +=
                        "Content-Type: " + this.artworkContentType + "\r\n" +
                        "Content-Length: " + this.artwork.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.Unicode.GetBytes(u)).ToArray().Concat(this.artwork).ToArray();
                    break;
                case TEARDOWN:
                    request = request.Concat(this.makeHead("TEARDOWN", "", di)).Concat(Encoding.ASCII.GetBytes("\r\n")).ToArray();
                    this.cleanup("stopped");
                    break;
                default:
                    break;
            }
            ExecRequest(request, getResponse);

        }

        public byte[] daapEncodeList(string field, bool enc, byte[][] args)
        {
            byte[] value = new byte[0];
            foreach( byte[] i in args)
            {
                value = value.Concat(i).ToArray();
            };
            byte[] buf = new byte[field.Length + 4];
            Encoding.UTF8.GetBytes(field).CopyTo(buf, 0);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)(value.Length)), 0, buf, field.Length, 4);
            return buf.Concat(value).ToArray();
        }

        public byte[] daapEncode(string field, string value, bool enc)
        {
            var valuebuf = Encoding.UTF8.GetBytes(value);
            var buf = new byte[field.Length + valuebuf.Length + 4];
            Encoding.UTF8.GetBytes(field).CopyTo(buf, 0);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)(valuebuf.Length)), 0, buf, field.Length, 4);
            Array.Copy(valuebuf, 0, buf, field.Length + 4, valuebuf.Length);
            return buf;
        }

        public void parsePorts(string headers)
        {
            // server_port=57402;control_port=57324;timing_port=0
            
            //string? parsePort(string name, string transport)
            //{
            //    var re = new RegExp(name + "=(\\d+)");
            //    var res = re.exec(transport);

            //    return res ? parseInt(res[1]) : null;
            //}

            //var transport = headers["Transport"],
            //    rtspConfig = {
            //        audioLatency: parseInt(headers["Audio-Latency"]),
            //        requireEncryption: this.requireEncryption
            //    },
            //    names = ["server_port", "control_port", "timing_port"];

            //  for(var i = 0; i<names.length; i++) {
            //    var name = names[i];
            //        var port = parsePort(name, transport);

            //    if(port === null) {
            //        if (this.debug) console.log("parseport");
            //      // this.cleanup("parse_ports", transport);
            //      // return false;
            //      rtspConfig[name] = 4533;
            //    } else
            //      rtspConfig[name] = port;
            //  }

            //this.emit("config", rtspConfig);

            //return true;
        }

        public string parseAuthenticate(string auth, string field)
        {
            //var re = new RegExp(field + "="([^"]+)""),
            //    res = re.exec(auth);

            //return res ? res[1] : null;
            return "";
        }

        public void processData(byte[] blob)
        {
            string responseText = Encoding.UTF8.GetString(blob);
            // Get the headers
            string[] headers = responseText.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.None);
            string[] headerLines = headers[0].Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string[] statusLine = headerLines[0].Split(" ");
            int status = int.Parse(statusLine[1]);
            string[] headerFields = new string[headerLines.Length - 1];
            Array.Copy(headerLines, 1, headerFields, 0, headerLines.Length - 1);
            Dictionary<string, string> headerDict = new Dictionary<string, string>();
            foreach (string headerField in headerFields)
            {
                string[] headerFieldParts = headerField.Split(new string[] { ": " }, StringSplitOptions.None);
                headerDict.Add(headerFieldParts[0], headerFieldParts[1]);
            }
            // Get the body in raw byte  form
            byte[] body = new byte[0];
            if (headers.Length > 1)
            {
                body = blob.Skip(headers[0].Length + 4).ToArray();
            }
            // Get the body in string form
            string bodyText = Encoding.UTF8.GetString(body);

            // Detect 453, 401

            if (this.status != OPTIONS && this.mode == 0)
            {
                if (status == 401)
                {
                    if (this.password == null)
                    {
                        if (this.debug) Console.WriteLine("nopass");
                        if (this.status == OPTIONS2)
                        {
                            emitEnd?.Invoke("pair_failed","");
                            this.cleanup("no_password");
                        }
                        return;
                    }

                    if (status == 455)
                    {

                        return;
                    }


                    if (this.passwordTried)
                    {
                        if (this.debug) Console.WriteLine("badpass");
                        emitEnd?.Invoke("pair_failed", "");
                        this.cleanup("bad_password");

                        return;
                    }
                    else
                        this.passwordTried = true;

                    var auth = headerDict["WWW-Authenticate"];
                    
                    DI di = new DI();
                    di.realm = parseAuthenticate(auth, "realm");
                    di.nonce = parseAuthenticate(auth, "nonce");
                    di.username = "Radioline";
                    di.password = this.password;
                    this.sendNextRequest(di:di);
                    return;
                }

                if (status == 453)
                {
                    if (this.debug) Console.WriteLine("busy");
                    this.cleanup("busy");
                    return;
                }

                if (status != 200)
                {
                        if (this.status != SETVOLUME && this.status != SETPEERS && this.status != FLUSH && this.status != RECORD && this.status != GETVOLUME && this.status != SETPROGRESS && this.status != SETDAAP && this.status != SETART)
                        {
                            if ((new int[] {PAIR_VERIFY_1,
                              PAIR_VERIFY_2,
                              AUTH_SETUP,
                              PAIR_PIN_START,
                              PAIR_PIN_SETUP_1,
                              PAIR_PIN_SETUP_2,
                              PAIR_PIN_SETUP_3}).Contains(this.status))
                        {
                            emitEnd?.Invoke("pair_failed","");
                        }
                        this.cleanup(status.ToString());
                        return;
                    }
                }
            }
            
            // password was accepted (or not needed)
            this.passwordTried = false;

            // Parse the body
            switch (this.status)
            {
                case PAIR_PIN_START:
                    if (!this.transient) { emitNeedPassword?.Invoke(); }
                    this.status = this.airplay2 ? PAIR_SETUP_1 : PAIR_PIN_SETUP_1;
                    if (!this.transient) { return; }
                    break;
                case PAIR_PIN_SETUP_1:
                    var N = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294" +
                            "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
                            "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB" +
                            "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74" +
                            "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A" +
                            "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D" +
                            "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73" +
                            "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
                            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F" +
                            "9E4AFF73";
                    var customParams = SrpParameters.Create<SHA1>(N, "02");
                    this.srp = new SrpClient();
                    this.P = this.password;
                    var pps1_bplist = BinaryPropertyListParser.Parse(body) as NSDictionary;
                    Console.WriteLine(BinaryPropertyListParser.Parse(body).ToXmlPropertyList());
                    this.s = Convert.ToHexString((pps1_bplist.Get("salt") as NSData).Bytes);
                    this.B = Convert.ToHexString((pps1_bplist.Get("pk") as NSData).Bytes);
                    NSDictionary dict = new NSDictionary();
                    // SRP: Generate random auth_secret, "a"; if pairing is successful, it"ll be utilized in
                    // subsequent session authentication(s).

                    // SRP: Compute A and M1.
                    var srpEphemeral = this.srp.GenerateEphemeral();
                    this.a = srpEphemeral.Secret;
                    this.A = srpEphemeral.Public;            
                    this.M1 = this.srp.DeriveSession(srpEphemeral.Secret, this.P, this.s, srpEphemeral.Secret, this.B).Proof;
                    this.status = PAIR_PIN_SETUP_2;
                    break;
                case PAIR_PIN_SETUP_2:
                    Dictionary<string, string> pps2_dict = LegacyATVVerifier.confirm(this.a, this.M1);
                    this.epk = pps2_dict["epk"];
                    this.authTag = pps2_dict["authTag"];
                    this.status = PAIR_PIN_SETUP_3;
                    break;
                case PAIR_PIN_SETUP_3:
                    this.status = PAIR_VERIFY_1;
                    this.authSecret = this.a;
                    break;
                case PAIR_VERIFY_1:
                    string atv_pub = Convert.ToHexString(body.Skip(0).Take(32).ToArray());
                    string atv_data  = Convert.ToHexString(body.Skip(32).ToArray());

                    string shared    = LegacyATVVerifier.shared(v_pri: this.pair_verify_1_verifier["v_pri"], atv_pub);
                    string signed    = LegacyATVVerifier.signed(this.authSecret, this.pair_verify_1_verifier["v_pub"], atv_pub);
                    this.pair_verify_1_signature = (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(Convert.FromHexString(LegacyATVVerifier.signature(shared, atv_data, signed))).ToArray();
                    this.status = PAIR_VERIFY_2;
                    break;
                case PAIR_VERIFY_2:
                    this.status = this.mode == 2 ? AUTH_SETUP : OPTIONS;
                    break;
                case PAIR_SETUP_1:
                    let buf2 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      let databuf1 = tlv.decode(buf2);
                    if (this.debug) console.log(databuf1)
      if (databuf1[tlv.Tag.BackOff])
                    {
                        let backOff = databuf1[tlv.Tag.BackOff];
                        console.log(backOff)
        let seconds = Buffer.from(backOff).readInt16LE(0, backOff.byteLength);

                        console.log("You"ve attempt to pair too recently. Try again in " + (seconds) + " seconds.");

                    }
                    if (databuf1[tlv.Tag.ErrorCode])
                    {
                        let buffer = databuf1[tlv.Tag.ErrorCode];
                        console.log("Device responded with error code " + Buffer.from(buffer).readIntLE(0, buffer.byteLength) + ". Try rebooting your Apple TV.");
                    }
                    if (databuf1[tlv.Tag.PublicKey])
                    {
                        this._atv_pub_key = databuf1[tlv.Tag.PublicKey]
                      this._atv_salt = databuf1[tlv.Tag.Salt]
                    this._hap_genkey = crypto.randomBytes(32);
                        if (this.password == null)
                        {
                            this.password = 3939 // transient
      }
                        this.srp = new SrpClient(SRP.params.hap, Buffer.from(this._atv_salt), Buffer.from("Pair-Setup"), Buffer.from(this.password.toString()), Buffer.from(this._hap_genkey), true)
                    this.srp.setB(this._atv_pub_key)
                    this.A = this.srp.computeA()
                    this.M1 = this.srp.computeM1()
                    this.status = PAIR_SETUP_2}
                    else
                    {
                        this.emit("pair_failed");
                        this.cleanup("pair_failed");
                        return;
                    }
                    break;
                case PAIR_SETUP_2:
                    let buf3 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      let databuf2 = tlv.decode(buf3);
                    this.deviceProof = databuf2[tlv.Tag.Proof];
                    // console.log("DEBUG: Device Proof=" + this.deviceProof.toString("hex"));
                    this.srp.checkM2(this.deviceProof);
                    if (this.transient == true)
                    {
                        this.credentials = new Credentials(
                          "sdsds",
                          "",
                          "",
                          "",
                          this.seed
                        );
                        this.credentials.writeKey = enc.HKDF(
                          "sha512",
                          Buffer.from("Control-Salt"),
                          this.srp.computeK(),
                          Buffer.from("Control-Write-Encryption-Key"),
                          32
                        );
                        this.credentials.readKey = enc.HKDF(
                          "sha512",
                          Buffer.from("Control-Salt"),
                          this.srp.computeK(),
                          Buffer.from("Control-Read-Encryption-Key"),
                          32
                        );
                        this.encryptedChannel = true
                      console.log(this.srp.computeK())
                      this.status = SETUP_AP2_1
                    }
                    else
                    {
                        this.status = PAIR_SETUP_3
                    }
                    break;
                case PAIR_SETUP_3:
                    let buf4 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      let encryptedData = tlv.decode(buf4)[tlv.Tag.EncryptedData];
                    let cipherText = encryptedData.slice(0, -16);
                    let hmac = encryptedData.slice(-16);
                    let decrpytedData = enc.verifyAndDecrypt(cipherText, hmac, null, Buffer.from("PS-Msg06"), this.encryptionKey);
                    let tlvData = tlv.decode(decrpytedData);
                    this.credentials = new Credentials(
                       "sdsds",
                       tlvData[tlv.Tag.Username],
                       this.pairingId,
                       tlvData[tlv.Tag.PublicKey],
                      this.seed
                     );
                    this.status = PAIR_VERIFY_HAP_1;
                    break;
                case PAIR_VERIFY_HAP_1:
                    let buf5 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
                  let decodedData = tlv.decode(buf5);
                    let sessionPublicKey = decodedData[tlv.Tag.PublicKey];
                    let encryptedData1 = decodedData[tlv.Tag.EncryptedData];

                    if (sessionPublicKey.length != 32)
                    {
                        throw new Error(`sessionPublicKey must be 32 bytes(but was ${ sessionPublicKey.length })`);
                    }

                    let cipherText1 = encryptedData1.slice(0, -16);
                    let hmac1 = encryptedData1.slice(-16);
                    // let sharedSecret = curve25519.deriveSharedSecret(this.verifyPrivate, sessionPublicKey);
                    let sharedSecret = curve25519_js.sharedKey(this.verifyPrivate, sessionPublicKey)
                  let encryptionKey = enc.HKDF(
        "sha512",
        Buffer.from("Pair-Verify-Encrypt-Salt"),
        sharedSecret,
        Buffer.from("Pair-Verify-Encrypt-Info"),
        32
      );
                    let decryptedData = enc.verifyAndDecrypt(cipherText1, hmac1, null, Buffer.from("PV-Msg02"), encryptionKey);
                    this.verifier_hap_1 = {
                    sessionPublicKey: sessionPublicKey,
        sharedSecret: sharedSecret,
        encryptionKey: encryptionKey,
        pairingData: decryptedData
                  }
                    this.status = PAIR_VERIFY_HAP_2;
                    this.sharedSecret = sharedSecret;
                    break;
                case PAIR_VERIFY_HAP_2:
                    let buf6 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      this.credentials.readKey = enc.HKDF(
        "sha512",
        Buffer.from("Control-Salt"),
        this.verifier_hap_1.sharedSecret,
        Buffer.from("Control-Read-Encryption-Key"),
        32
      );
                    this.credentials.writeKey = enc.HKDF(
                      "sha512",
                      Buffer.from("Control-Salt"),
                      this.verifier_hap_1.sharedSecret,
                      Buffer.from("Control-Write-Encryption-Key"),
                      32
                    );
                    if (this.debug) { console.log("write", this.credentials.writeKey)}
                    if (this.debug) { console.log("buf6", buf6)}
                    this.encryptedChannel = true
      this.status = (this.mode == 2 ? AUTH_SETUP : SETUP_AP2_1)
    break;
                case SETUP_AP2_1:
                    console.log("timing port parsing")
      let buf7 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      let sa1_bplist = bplistParser.parseBuffer(buf7)
      this.eventPort = sa1_bplist[0]["eventPort"]
      if (sa1_bplist[0]["timingPort"])
                        this.timingDestPort = sa1_bplist[0]["timingPort"]
      console.log("timing port ok", sa1_bplist[0]["timingPort"])
      // let rtspConfig1 = {
      //   audioLatency: 50,
      //   requireEncryption: false,
      //   server_port : 22223,
      //   control_port : this.controlPort,
      //   timing_port : this.timingPort,
      //   event_port: this.eventPort,
      //   credentials : this.credentials
      // }
      // this.emit("config", rtspConfig1);

                    // this.eventsocket.bind(3003, this.socket.address().address);
      this.status = SETPEERS
    break;
                case SETUP_AP2_2:
                    let buf8 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      let sa2_bplist = bplistParser.parseBuffer(buf8)
      let rtspConfig = {
        audioLatency: 50,
        requireEncryption: false,
        server_port: sa2_bplist[0]["streams"][0]["dataPort"],
        control_port: sa2_bplist[0]["streams"][0]["controlPort"],
        timing_port: this.timingDestPort ? this.timingDestPort : this.timingPort,
        credentials: this.credentials
      }
            this.timingsocket.close();
            this.controlsocket.close();
            this.emit("config", rtspConfig);
            console.log("goto info")
      // this.session = 1;
      this.status = RECORD;
            // this.emit("ready");
            break;
    case SETPEERS:
            this.status = SETUP_AP2_2;
            break;
    case FLUSH:
            this.status = PLAYING
      this.emit("pair_success");
            this.session = "1"
      console.log("flush")
      this.emit("ready");
            // console.log(sa2_bplist[0]["streams"][0]["controlPort"], sa2_bplist[0]["streams"][0]["dataPort"] )

            break;
    case INFO:
            let buf9 = Buffer.from(rawData).slice(rawData.length - parseInt(headers["Content-Length"]), rawData.length)
      this.status = (this.credentials) ? RECORD : PAIR_SETUP_1
    break;
    case GETVOLUME:
            this.status = RECORD
    break;
    case AUTH_SETUP:
            this.status = this.airplay2 ? SETUP_AP2_1 : OPTIONS
    break;
    case OPTIONS:
            /*
             * Devices like Apple TV and Zeppelin Air do not support encryption.
             * Only way of checking that: they do not reply to Apple-Challenge
             */
            if (headers["Apple-Response"])
                this.requireEncryption = true;
            // console.log("yeah22332",headers["WWW-Authenticate"],response.code)
            if (headers["WWW-Authenticate"] != null & response.code === 401)
            {
                let auth = headers["WWW-Authenticate"];
                let realm = parseAuthenticate(auth, "realm");
                let nonce = parseAuthenticate(auth, "nonce");
                let uri = "*"
                let user = "iTunes"
                let methodx = "OPTIONS"
                let pwd = this.password
                ha1 = md5norm(`${ user}:${ realm}:${ pwd}`)
          ha2 = md5norm(`${ methodx}:${ uri}`)
          di_response = md5(`${ ha1}:${ nonce}:${ ha2}`)
          this.code_digest = `Authorization: Digest username = "${user}", realm = "${realm}", nonce = "${nonce}", uri = "${uri}", response = "${di_response}" \r\n\r\n`
          this.status = OPTIONS2;
            }
            else
            {

                this.status = this.session ? PLAYING : (this.airplay2 ? PAIR_PIN_START : ANNOUNCE);
                if (this.status == ANNOUNCE) { this.emit("pair_success")};
            }

            break;
    case OPTIONS2:
            /*
             * Devices like Apple TV and Zeppelin Air do not support encryption.
             * Only way of checking that: they do not reply to Apple-Challenge
             */
            // if(headers["Apple-Response"])
            //   this.requireEncryption = true;
            this.status = this.session ? PLAYING : (this.airplay2 ? SETUP_AP2_1 : ANNOUNCE);
            if (this.status == ANNOUNCE) { this.emit("pair_success")};


            break;
    case ANNOUNCE:
            this.status = SETUP;
            break;

    case SETUP:
            this.status = RECORD;
            this.session = headers["Session"];
            this.parsePorts(headers);
            break;

    case RECORD:
            if (!this.airplay2)
            {
                this.session = this.session ?? "1"
            this.emit("ready")};
            this.status = SETVOLUME;
            break;

    case SETVOLUME:
            this.status = this.airplay2 ? FLUSH : PLAYING;
            break;
    case SETPROGRESS:
            this.status = PLAYING;
            break;
    case SETDAAP:
            this.status = PLAYING;
            break;

    case SETART:
            this.status = PLAYING;
            break;
        }

  if (this.callback != null) {
            this.callback();
        }

  this.sendNextRequest();
}






}

    }

}
