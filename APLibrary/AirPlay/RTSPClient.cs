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
    public delegate void EmitPairSuccess();
    public delegate void EmitReady();
    public delegate void NeedPassword();
    public delegate void EmitRTSPConfig(RTSPConfig rtspConfig);
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
        private long? progress;
        private long? duration;
        private long? starttime;
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
        private Dictionary<string, string>? pair_verify_1_verifier;
        private byte[] pair_verify_1_signature;
        private string code_digest;
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
        private byte[] deviceProof;
        private SrpClient? srp;
        private string I = "366B4165DD64AD3A";
        private string P;
        private string s;
        private string B;
        private string A;
        private string a;
        private byte[] Al;
        private string M1;
        private SrpSession M1Session;
        private string epk;
        private string authTag;
        private string _atv_salt;
        private string _atv_pub_key;
        private string _hap_genkey;
        private byte[] _hap_encrypteddata;
        private string? pairingId;
        private byte[] K;
        private byte[] seed;
        private byte[] sharedSecret;
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
        public event EmitRTSPConfig emitRTSPConfig;
        public event EmitPairSuccess emitPairSuccess;
        public event EmitReady emitReady;
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
        
        private string[] rtsp_methods = new string[] {"INFO",
        "OPTIONS",
        "ANNOUNCE",
        "SETUP",
        "RECORD",
        "SETVOLUME",
        "PLAYING",
        "TEARDOWN",
        "CLOSED",
        "SETDAAP",
        "SETART",
        "PAIR_VERIFY_1",
        "PAIR_VERIFY_2",
        "OPTIONS2",
        "AUTH_SETUP",
        "PAIR_PIN_START",
        "PAIR_PIN_SETUP_1",
        "PAIR_PIN_SETUP_2",
        "PAIR_PIN_SETUP_3",
        "PAIR_SETUP_1",
        "PAIR_SETUP_2",
        "PAIR_SETUP_3",
        "PAIR_VERIFY_HAP_1",
        "PAIR_VERIFY_HAP_2",
        "SETUP_AP2_1",
        "SETUP_AP2_2",
        "SETPEERS",
        "FLUSH",
        "GETVOLUME",
        "SETPROGRESS"};

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
            this.controlPort = ((IPEndPoint)udpServers.controlSocket.LocalEndPoint).Port;
            this.timingPort = 17459;
            this.hostip = host;

            this.socket = new TcpClient();
            this.socket.ReceiveTimeout = 400000000;
            this.socket.SendTimeout = 400000000;
            this.socket.ConnectAsync(host, int.Parse(port)).ContinueWith(task => {
                Debug.WriteLine("OKAY" + host + port);
                nsctrl = this.socket.GetStream();
                srctrl = new StreamReader(nsctrl);
                // this.clearTimeout();

                if (this.needPassword == true)
                {
                    Debug.WriteLine("s1");
                    this.status = PAIR_PIN_START;
                    this.sendNextRequest();
                    this.startHeartBeat();
                }
                else
                {
                    if (this.mode != 2)
                    {
                        Debug.WriteLine("s2");
                        if (this.debug) Debug.WriteLine("AUTH_SETUP", "nah");
                        this.status = OPTIONS;
                        this.sendNextRequest();
                        this.startHeartBeat();
                    }
                    else
                    {
                        Debug.WriteLine("s3");
                        this.status = AUTH_SETUP;
                        if (this.debug) Debug.WriteLine("AUTH_SETUP", "yah");
                        this.sendNextRequest();
                        this.startHeartBeat();
                    }


                }
            });

        }

        public void ExecRequest(byte[] input, bool GetResponse) {
            Debug.WriteLine("GetResponse: " + GetResponse.ToString());
            Debug.WriteLine("Current status:" + rtsp_methods[this.status+1]);
            Debug.WriteLine(Encoding.UTF8.GetString(input));
            if (this.encryptedChannel && this.credentials != null)
            {
                input = this.credentials.encrypt(input);
            }
            nsctrl.Write(input, 0, input.Length);

            if (!GetResponse)
                return;

            byte[] res;
            int lastRead = 0;
            
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buffer = new byte[4096];
                do
                {
                    lastRead = nsctrl.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, lastRead);
                } while (lastRead > buffer.Length);
                res = ms.ToArray();
                if (this.encryptedChannel && this.credentials != null)
                {
                    res = this.credentials.decrypt(res);
                }
                if (Encoding.UTF8.GetString(res) == "")
                {
                    this.cleanup("done");
                }
                Debug.WriteLine("Received:");
                Debug.WriteLine(Encoding.UTF8.GetString(res));
                processData(res);
            }




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

            return System.Text.Encoding.UTF8.GetBytes(head);
        }

        public byte[] makeHeadWithURL(string method, DI digestInfo)
        {
            return this.makeHead(method, "rtsp://" + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString() + "/" + this.announceId, digestInfo);
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
                    Debug.WriteLine("HMM");
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
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
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
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
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
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
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
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case PAIR_VERIFY_1:
                    request = request.Concat(this.makeHead("POST", "/pair-verify", null, true)).ToArray();
                    u += "Content-Type: application/octet-stream\r\n";
                    this.pair_verify_1_verifier = LegacyATVVerifier.verifier(this.authSecret);
                    u += "Content-Length:" + this.pair_verify_1_verifier["verifierBody"].Length + "\r\n\r\n";

                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(Convert.FromHexString(this.pair_verify_1_verifier["verifierBody"])).ToArray();
                    break;
                case PAIR_VERIFY_2:
                    request = request.Concat(this.makeHead("POST", "/pair-verify", null, true)).ToArray();
                    u += "Content-Type: application/octet-stream\r\n";
                    u += "Content-Length:" + this.pair_verify_1_signature.Length + "\r\n\r\n";

                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(this.pair_verify_1_signature).ToArray();
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
                        Debug.WriteLine(new byte[] { 0x00000010 }.Length);
                        dic1.Add(TlvTag.Sequence, new byte[] { 0x01 });
                        dic1.Add(TlvTag.PairingMethod, new byte[] { 0x00 });
                        dic1.Add(TlvTag.Flags, new byte[] { 0x00000010 });
                        byte[] ps1x = Tlv.Encode(dic1);

                        u += "Content-Length: " + ps1x.Length + "\r\n";
                        u += "Content-Type: application/octet-stream" + "\r\n\r\n";
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps1x).ToArray();
                    }
                    else
                    {
                        Dictionary<byte, byte[]> dic2 = new Dictionary<byte, byte[]>();
                        dic2.Add(TlvTag.PairingMethod, new byte[] { 0x00 });
                        dic2.Add(TlvTag.Sequence, new byte[] { 0x01 });
                        dic2.Add(TlvTag.Flags, new byte[] { 0x00000010 });
                        byte[] ps2x = Tlv.Encode(dic2);
                        u += "Content-Length: " + ps2x.Length + "\r\n";
                        u += "Content-Type: application/octet-stream" + "\r\n\r\n";
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps2x).ToArray();
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
                    dic.Add(TlvTag.Sequence, new byte[] { 0x03 });
                    dic.Add(TlvTag.PublicKey, Convert.FromHexString(this.A));
                    dic.Add(TlvTag.Proof, Convert.FromHexString(this.M1));
                    var ps2 = Tlv.Encode(dic);
                    u += "Content-Length: " + ps2.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps2).ToArray();
                    break;
                case PAIR_SETUP_3:
                    request = request.Concat(this.makeHead("POST", "/pair-setup", null, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "X-Apple-HKP: " + this.homekitver + "\r\n";
                    u += "Content-Type: application/octet-stream\r\n";
                    this.K = Convert.FromHexString(this.srp.DeriveSession(this._hap_genkey, this._atv_pub_key, this._atv_salt, "Pair-Setup", this.srp.DerivePrivateKey(this._atv_salt, "Pair-Setup", this.password)).Key);
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
                    dic3b.Add(TlvTag.Sequence, new byte[] { 0x05 });
                    dic3b.Add(TlvTag.EncryptedData, encryptedTLV.Concat(encryptedTLVhmac).ToArray());
                    byte[] ps3xb = Tlv.Encode(dic3b);
                    u += "Content-Length: " + ps3xb.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps3xb).ToArray();
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
                    dic4.Add(TlvTag.Sequence, new byte[] { 0x01 });
                    dic4.Add(TlvTag.PublicKey, this.verifyPublic);
                    byte[] ps4 = Tlv.Encode(dic4);
                    u += "Content-Length: " + ps4.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps4).ToArray();
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
                    dic5b.Add(TlvTag.Sequence, new byte[] { 0x03 });
                    dic5b.Add(TlvTag.EncryptedData, encryptedTLV1.Concat(encryptedTLV1Hmac).ToArray());
                    byte[] ps5b = Tlv.Encode(dic5b);
                    u += "Content-Length: " + ps5b.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(ps5b).ToArray();
                    break;
                case AUTH_SETUP:
                    request = request.Concat(this.makeHead("POST", "/auth-setup", di)).ToArray();
                    u += "Content-Length:" + "33" + "\r\n\r\n";
                    byte[] auth_fakekey_buf = new byte[] {0x01, // unencrypted
                            0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, // static Curve 25519 key
                            0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82, 0x07,
                            0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b,
                            0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d, 0x4e};
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(auth_fakekey_buf).ToArray();
                    break;
                case OPTIONS:
                    request = request.Concat(this.makeHead("OPTIONS", "*", di)).ToArray();
                    if (this.airplay2)
                    {
                        u += "User-Agent: AirPlay/409.16\r\n";
                        u += "Connection: keep-alive\r\n";
                    }
                    u += "Apple-Challenge: SdX9kFJVxgKVMFof/Znj4Q\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    break;
                case OPTIONS2:
                    request = request.Concat(this.makeHead("OPTIONS", "*", di)).ToArray();
                    u += this.code_digest;
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    break;
                case ANNOUNCE:
                    if (this.announceId == null)
                    {
                        this.announceId = Utils.Utils.randomInt(10).ToString();
                    }

                    string body =
                      "v=0\r\n" +
                      "o=iTunes " + this.announceId + " 0 IN IP4 " + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString() + "\r\n" +
                      "s=iTunes\r\n" +
                      "c=IN IP4 " + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString() + "\r\n" +
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
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    //console.log(request);
                    break;
                case SETUP:
                    request = request.Concat(this.makeHeadWithURL("SETUP", di)).ToArray();
                    u += "Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;" +
                      "control_port=" + this.controlPort + ";" +
                      "timing_port=" + this.timingPort + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    //console.log(request);
                    break;
                case INFO:
                    request = request.Concat(this.makeHead("GET", "/info", di, true)).ToArray();
                    u += "User-Agent: AirPlay/409.16\r\n";
                    u += "Connection: keep-alive\r\n";
                    u += "CSeq: " + this.nextCSeq() + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
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
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case SETPEERS:
                    request = request.Concat(this.makeHeadWithURL("SETPEERS", di)).ToArray();
                    u += "Content-Type: /peer-list-changed\r\n";
                    using (var memoryStream = new MemoryStream())
                    {
                        BinaryPropertyListWriter bplist = new BinaryPropertyListWriter(memoryStream);
                        NSArray dictv = new NSArray {this.hostip,((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString()};
                        //dictv.Insert(0,this.hostip);
                        //dictv.Insert(1,();
                        bplist.Write(dictv);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(bpbuf).ToArray();
                    };
                    break;
                case FLUSH:
                    request = request.Concat(this.makeHeadWithURL("FLUSH", di)).ToArray();
                    u += this.makeRtpInfo() + "\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
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
                        NSArray array = new NSArray { stream};
                        streams.Add("streams", array);
                        bplist.Write(streams);
                        byte[] bpbuf = memoryStream.ToArray();

                        u += "Content-Length:" + bpbuf.Length + "\r\n\r\n";
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).Concat(bpbuf).ToArray();
                    }

                    break;
                case RECORD:
                    if (this.airplay2 != null && this.credentials != null) {
                        if (this.announceId == null)
                        {
                            this.announceId = Utils.Utils.randomInt(10).ToString();
                        }
                        var nextSeq = this.audioOut.lastSeq + 10;
                        var rtpSyncTime = nextSeq * 352 + 2 * 44100;
                        request = request.Concat(this.makeHead("RECORD", "rtsp://" + ((IPEndPoint)this.socket?.Client.LocalEndPoint).Address.MapToIPv4().ToString() + "/" + this.announceId, di, true)).ToArray();
                        u += "CSeq: " + ++this.cseq + "\r\n";
                        u += "User-Agent: AirPlay/409.16" + "\r\n";
                        u += "Client-Instance: " + this.dacpId + "\r\n";
                        u += "DACP-ID: " + this.dacpId + "\r\n";
                        u += "Active-Remote: " + this.activeRemote + "\r\n";
                        u += "X-Apple-ProtocolVersion: 1\r\n";
                        u += "Range: npt=0-\r\n";
                        u += this.makeRtpInfo() + "\r\n";
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    } else {
                        request = request.Concat(this.makeHeadWithURL("RECORD", di)).ToArray();
                        u += "Range: npt=0-\r\n";
                        u += this.makeRtpInfo() + "\r\n";
                        request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    }
                    break;
                case GETVOLUME:
                    string body1 = "volume\r\n";
                    request = request.Concat(this.makeHeadWithURL("GET_PARAMETER", di)).ToArray();
                    u +=
                       "Content-Type: text/parameters\r\n" +
                       "Content-Length: " + body1.Length + "\r\n\r\n";
                    u += body1;
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    break;
                case SETVOLUME:
                    var attenuation =
                              this.volume == 0.0 ?
                              -144.0 :
                              (-30.0) * (100 - this.volume) / 100.0;

                    string body2 = "volume: " + attenuation.ToString() + "\r\n";

                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u +=
                              "Content-Type: text/parameters\r\n" +
                              "Content-Length: " + body2.Length + "\r\n\r\n";

                    u += body2;
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    break;
                case SETPROGRESS:
                    string hms(int seconds) {
                        return TimeSpan.FromSeconds(seconds).ToString(@"hh\:mm\:ss");
                    }
                    int position = (int)(this.starttime + (this.progress) * (int)(Math.Floor((2 * 44100) / (352 / 125) / 0.71)));
                    int duration = (int)(this.starttime + (this.duration) * (int)(Math.Floor((2 * 44100) / (352 / 125) / 0.71)));
                    string body3 = "progress: " + this.starttime.ToString() + "/" + position.ToString() + "/" + duration.ToString() + "\r\n";
                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u +=
                              "Content-Type: text/parameters\r\n" +
                              "Content-Length: " + body3.Length + "\r\n\r\n";
                    u += body3;
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray();
                    break;
                case SETDAAP:
                    bool daapenc = true;
                    //daapenc = true
                    byte[] name = this.daapEncode("minm", this.trackInfo["name"], daapenc);
                    byte[] artist = this.daapEncode("asar", this.trackInfo["artist"], daapenc);
                    byte[] album = this.daapEncode("asal", this.trackInfo["album"], daapenc);
                    byte[][] trackargs = new byte[][] { name, artist, album };

                    byte[] daapInfo = this.daapEncodeList("mlit", daapenc, trackargs);

                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u += this.makeRtpInfo();
                    u +=
                    "Content-Type: application/x-dmap-tagged\r\n" +
                    "Content-Length: " + daapInfo.Length + "\r\n\r\n";

                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(daapInfo).ToArray();
                    break;
                case SETART:
                    request = request.Concat(this.makeHeadWithURL("SET_PARAMETER", di)).ToArray();
                    u += this.makeRtpInfo();
                    u +=
                        "Content-Type: " + this.artworkContentType + "\r\n" +
                        "Content-Length: " + this.artwork.Length + "\r\n\r\n";
                    request = request.Concat(Encoding.UTF8.GetBytes(u)).ToArray().Concat(this.artwork).ToArray();
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
            foreach (byte[] i in args)
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

        public void parsePorts(Dictionary<string,string> headers)
        {
            // Get port from Transport header with regex
            // server_port=57402;control_port=57324;timing_port=0
            string portRegex = @"server_port=(\d+);control_port=(\d+);timing_port=(\d+)";
            Regex r = new Regex(portRegex);
            Match m = r.Match(headers["Transport"]);
         
            if (m.Success)
            {
                RTSPConfig rtspConfig = new RTSPConfig();
                rtspConfig.audioLatency = 50;
                rtspConfig.requireEncryption = this.requireEncryption;
                rtspConfig.server_port = int.Parse(m.Groups[1].Value);
                rtspConfig.control_port = int.Parse(m.Groups[2].Value);
                rtspConfig.timing_port = int.Parse(m.Groups[3].Value);
                rtspConfig.credentials = this.credentials;

                emitRTSPConfig?.Invoke(rtspConfig);
            }



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
            // Get realm or nonce from WWW-Authenticate header with regex
            // WWW - Authenticate: Digest realm = "raop", nonce = "ddfd59b4aea7bbbcbbb3b60d3b2768b7"
            string authRegex = field + "=\"([^\"]+)\"";
            Regex r = new Regex(authRegex);
            Match m = r.Match(auth);
            if (m.Success)
            {
                return m.Groups[1].Value;
            } else
            {
                return "";
            }

        }

        public void processData(byte[] blob)
        {
            string responseText = Encoding.UTF8.GetString(blob);
            // Get the headers
            string[] headers = responseText.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.None);
            string[] headerLines = headers[0].Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string[] statusLine = headerLines[0].Split(" ");
            int status = 200;
            try
            {
                int.Parse(statusLine[1]);
            }
            catch (Exception _) {
            }
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
            Debug.WriteLine(status.ToString());
            if (this.status != OPTIONS && this.mode == 0)
            {
                if (status == 401)
                {
                    if (this.password == null)
                    {
                        if (this.debug) Debug.WriteLine("nopass");
                        if (this.status == OPTIONS2)
                        {
                            emitEnd?.Invoke("pair_failed", "");
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
                        if (this.debug) Debug.WriteLine("badpass");
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
                    this.sendNextRequest(di: di);
                    return;
                }

                if (status == 453)
                {
                    if (this.debug) Debug.WriteLine("busy");
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
                            emitEnd?.Invoke("pair_failed", "");
                        }
                        this.cleanup(status.ToString());
                        return;
                    }
                }
            }
            Debug.WriteLine(status.ToString());
            // password was accepted (or not needed)
            this.passwordTried = false;

            // Parse the body
            switch (this.status)
            {
                case PAIR_PIN_START:
                    if (!this.transient) { emitNeedPassword?.Invoke(); }
                    this.status = this.airplay2 ? PAIR_SETUP_1 : PAIR_PIN_SETUP_1;
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
                    Debug.WriteLine(BinaryPropertyListParser.Parse(body).ToXmlPropertyList());
                    this.s = Convert.ToHexString((pps1_bplist.Get("salt") as NSData).Bytes);
                    this.B = Convert.ToHexString((pps1_bplist.Get("pk") as NSData).Bytes);
                    NSDictionary dict = new NSDictionary();
                    // SRP: Generate random auth_secret, "a"; if pairing is successful, it"ll be utilized in
                    // subsequent session authentication(s).

                    // SRP: Compute A and M1.
                    var srpEphemeral = this.srp.GenerateEphemeral();
                    this.a = srpEphemeral.Secret;
                    this.A = srpEphemeral.Public;
                    this.M1 = this.srp.DeriveSession(this.a, this.B, this.s, this.I, this.srp.DerivePrivateKey(this.s, this.I, this.P)).Proof;
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
                    string atv_data = Convert.ToHexString(body.Skip(32).ToArray());

                    string shared = LegacyATVVerifier.shared(v_pri: this.pair_verify_1_verifier["v_pri"], atv_pub);
                    string signed = LegacyATVVerifier.signed(this.authSecret, this.pair_verify_1_verifier["v_pub"], atv_pub);
                    this.pair_verify_1_signature = (new byte[] { 0x00, 0x00, 0x00, 0x00 }).Concat(Convert.FromHexString(LegacyATVVerifier.signature(shared, atv_data, signed))).ToArray();
                    this.status = PAIR_VERIFY_2;
                    break;
                case PAIR_VERIFY_2:
                    this.status = this.mode == 2 ? AUTH_SETUP : OPTIONS;
                    break;
                case PAIR_SETUP_1:
                    Dictionary<byte, byte[]> databuf1 = Tlv.Decode(body);
                    if (databuf1.ContainsKey(TlvTag.BackOff)) {
                        byte[] backOff = databuf1[TlvTag.BackOff];
                        int seconds = EndianBitConverter.LittleEndian.ToInt16(backOff, 0);

                        Debug.WriteLine("You've attempt to pair too recently. Try again in " + (seconds.ToString()) + " seconds.");

                    }
                    if (databuf1.ContainsKey(TlvTag.ErrorCode))
                    {
                        byte[] buffer = databuf1[TlvTag.ErrorCode];
                        Debug.WriteLine("Device responded with error code " + Convert.ToSByte(buffer).ToString() + ". Try rebooting your Apple TV.");
                    }
                    if (databuf1.ContainsKey(TlvTag.PublicKey))
                    {
                        this._atv_pub_key = Convert.ToHexString(databuf1[TlvTag.PublicKey]);
                        this._atv_salt = Convert.ToHexString(databuf1[TlvTag.Salt]);
                        //this._hap_genkey = new byte[32];
                        //RandomNumberGenerator rng = RandomNumberGenerator.Create();
                        //rng.GetBytes(this._hap_genkey);
                        if (this.password == null)
                        {
                            this.password = "3939"; // transient
                        }
                        string SRP_AP2_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
                                "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
                                "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
                                "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
                                "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
                                "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
                                "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
                                "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
                                "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
                                "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
                                "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                                "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
                                "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
                        var customParams_ap2 = SrpParameters.Create<SHA512>(SRP_AP2_N, "05");
                        this.srp = new SrpClient(customParams_ap2);
                        //this.srp = new SrpClient(SRP.params.hap,
                        //Buffer.from(this._atv_salt), //salt
                        //Buffer.from("Pair-Setup"), //identity
                        //Buffer.from(this.password.toString()), //password
                        //Buffer.from(this._hap_genkey), true) // sec
                        var srpEphemeral2 = this.srp.GenerateEphemeral();
                        this._hap_genkey = srpEphemeral2.Secret;
                        this.A = srpEphemeral2.Public;
                        this.M1Session = this.srp.DeriveSession(this._hap_genkey, this._atv_pub_key, this._atv_salt, "Pair-Setup", this.srp.DerivePrivateKey(this._atv_salt, "Pair-Setup", this.password));
                        this.M1 = M1Session.Proof;
                        this.status = PAIR_SETUP_2;
                    } else {
                        this.emitEnd("pair_failed", "");
                        this.cleanup("pair_failed");
                        return;
                    }
                    break;
                case PAIR_SETUP_2:
                    Dictionary<byte, byte[]> databuf2 = Tlv.Decode(body);
                    this.deviceProof = databuf2[TlvTag.Proof];
                    // console.log("DEBUG: Device Proof=" + this.deviceProof.toString("hex"));
                    this.srp.VerifySession(this.A, this.M1Session, Convert.ToHexString(this.deviceProof));
                    if (this.transient == true)
                    {
                        this.credentials = new Credentials(
                          "sdsds",
                          new byte[0],
                          "",
                          new byte[0],
                          this.seed
                        );
                        this.credentials.writeKey = Encryption.HKDF(
                          Encoding.ASCII.GetBytes("Control-Salt"),
                          Convert.FromHexString(this.M1Session.Key),
                          Encoding.ASCII.GetBytes("Control-Write-Encryption-Key"),
                          32
                        );
                        Debug.WriteLine("hmm " + this.credentials.writeKey.Length);
                        this.credentials.readKey = Encryption.HKDF(
                          Encoding.ASCII.GetBytes("Control-Salt"),
                          Convert.FromHexString(this.M1Session.Key),
                          Encoding.ASCII.GetBytes("Control-Read-Encryption-Key"),
                          32
                        );
                        this.encryptedChannel = true;
                        this.status = SETUP_AP2_1;
                    }
                    else
                    {
                        this.status = PAIR_SETUP_3;
                    }
                    break;
                case PAIR_SETUP_3:
                    byte[] encryptedData = Tlv.Decode(body)[TlvTag.EncryptedData];
                    byte[] cipherText = encryptedData.Skip(0).Take(encryptedData.Length - 16).ToArray();
                    byte[] hmac = encryptedData.Skip(encryptedData.Length - 16).Take(16).ToArray();
                    byte[] decrpytedData = Encryption.VerifyAndDecrypt(cipherText, hmac, null, Encoding.ASCII.GetBytes("PS-Msg06"), this.encryptionKey);
                    Dictionary<byte, byte[]> tlvData = Tlv.Decode(decrpytedData);
                    this.credentials = new Credentials(
                       "sdsds",
                       tlvData[TlvTag.Username],
                       this.pairingId,
                       tlvData[TlvTag.PublicKey],
                      this.seed
                     );
                    this.status = PAIR_VERIFY_HAP_1;
                    break;
                case PAIR_VERIFY_HAP_1:
                    Dictionary<byte, byte[]> decodedData = Tlv.Decode(body);
                    byte[] sessionPublicKey = decodedData[TlvTag.PublicKey];
                    byte[] encryptedData1 = decodedData[TlvTag.EncryptedData];

                    if (sessionPublicKey.Length != 32)
                    {
                        throw new Exception(String.Format("sessionPublicKey must be 32 bytes(but was {0})", sessionPublicKey.Length));
                    }
                    byte[] cipherText1 = encryptedData1.Skip(0).Take(encryptedData1.Length - 16).ToArray();
                    byte[] hmac1 = encryptedData1.Skip(encryptedData1.Length - 16).Take(16).ToArray();
                    // let sharedSecret = curve25519.deriveSharedSecret(this.verifyPrivate, sessionPublicKey);
                    var curve25519 = new Curve25519();
                    curve25519.FromPrivateKey(this.verifyPrivate);
                    byte[] sharedSecret = curve25519.GetSharedSecret(sessionPublicKey);
                    byte[] encryptionKey = Encryption.HKDF(
                        Encoding.ASCII.GetBytes("Pair-Verify-Encrypt-Salt"),
                        sharedSecret,
                        Encoding.ASCII.GetBytes("Pair-Verify-Encrypt-Info"),
                        32
                    );
                    byte[] decryptedData = Encryption.VerifyAndDecrypt(cipherText1, hmac1, null, Encoding.ASCII.GetBytes("PV-Msg02"), encryptionKey);
                    this.verifier_hap_1 = new Dictionary<string, byte[]>();
                    this.verifier_hap_1.Add("sessionPublicKey", sessionPublicKey);
                    this.verifier_hap_1.Add("sharedSecret", sharedSecret);
                    this.verifier_hap_1.Add("encryptionKey", encryptionKey);
                    this.verifier_hap_1.Add("pairingData", decryptedData);
                    this.status = PAIR_VERIFY_HAP_2;
                    this.sharedSecret = sharedSecret;
                    break;
                case PAIR_VERIFY_HAP_2:
                    this.credentials.readKey = Encryption.HKDF(
                      Encoding.ASCII.GetBytes("Control-Salt"),
                      this.sharedSecret,
                      Encoding.ASCII.GetBytes("Control-Read-Encryption-Key"),
                      32
                    );
                    this.credentials.writeKey = Encryption.HKDF(
                      Encoding.ASCII.GetBytes("Control-Salt"),
                      this.sharedSecret,
                      Encoding.ASCII.GetBytes("Control-Write-Encryption-Key"),
                      32
                    );
                    //if (this.debug) { console.log("write", this.credentials.writeKey)}
                    //if (this.debug) { console.log("buf6", buf6)}
                    this.encryptedChannel = true;
                    this.status = (this.mode == 2 ? AUTH_SETUP : SETUP_AP2_1);
                    break;
                case SETUP_AP2_1:
                    Debug.WriteLine("timing port parsing");
                    NSDictionary sa1_bplist = BinaryPropertyListParser.Parse(body) as NSDictionary;
                    Debug.WriteLine(sa1_bplist.ToXmlPropertyList());
                    this.eventPort = ((NSNumber)sa1_bplist.ObjectForKey("eventPort")).ToInt();
                    if (sa1_bplist.TryGetValue("timingPort", out NSObject timingPort)) {
                        this.timingDestPort = ((NSNumber)sa1_bplist.ObjectForKey("timingPort")).ToInt();
                    }
                    Debug.WriteLine("timing port parsing ", this.eventPort.ToString());
                    this.status = SETPEERS;
                    
                    break;
                case SETUP_AP2_2:
                    NSDictionary sa2_bplist = BinaryPropertyListParser.Parse(body) as NSDictionary;
                    Debug.WriteLine(sa2_bplist.ToXmlPropertyList());
                    NSDictionary stream = ((NSArray)sa2_bplist.ObjectForKey("streams")).First() as NSDictionary;
                    RTSPConfig rtspConfig = new RTSPConfig();
                    rtspConfig.audioLatency = 50;
                    rtspConfig.requireEncryption = false;
                    rtspConfig.server_port = ((NSNumber)stream.ObjectForKey("dataPort")).ToInt();
                    rtspConfig.control_port = ((NSNumber)stream.ObjectForKey("controlPort")).ToInt();
                    rtspConfig.timing_port = (this.timingDestPort != null) ? this.timingDestPort : this.timingPort;
                    rtspConfig.credentials = this.credentials;

                    emitRTSPConfig?.Invoke(rtspConfig);
                    this.status = RECORD;
                    break;
                case SETPEERS:
                    this.status = SETUP_AP2_2;
                    break;
                case FLUSH:
                    this.status = PLAYING;
                    emitPairSuccess?.Invoke();
                    this.session = "1";
                    emitReady?.Invoke();
                    break;
                case INFO:
                    this.status = (this.credentials != null) ? RECORD : PAIR_SETUP_1;
                    break;
                case GETVOLUME:
                    this.status = RECORD;
                    break;
                case AUTH_SETUP:
                    this.status = this.airplay2 ? SETUP_AP2_1 : OPTIONS;
                    break;
                case OPTIONS:
                    /*
                     * Devices like Apple TV and Zeppelin Air do not support encryption.
                     * Only way of checking that: they do not reply to Apple-Challenge
                     */
                    if (headerDict.ContainsKey("Apple-Response"))
                        this.requireEncryption = true;
                    // console.log("yeah22332",headers["WWW-Authenticate"],response.code)
                    if (headerDict.ContainsKey("WWW-Authenticate") && status == 401)
                    {
                        string auth = headerDict["WWW-Authenticate"];
                        string realm = parseAuthenticate(auth, "realm");
                        string nonce = parseAuthenticate(auth, "nonce");
                        string uri = "*";
                        string user = "iTunes";
                        string methodx = "OPTIONS";
                        string pwd = this.password;
                        string ha1 = Utils.Utils.CreateMD5(user + ":" + realm + ":" + pwd);
                        string ha2 = Utils.Utils.CreateMD5(methodx + ":" + uri);
                        string di_response = Utils.Utils.CreateMD5(ha1 + ":" + nonce + ":" + ha2).ToUpper();
                        this.code_digest = String.Format("Authorization: Digest username = \"{0}\", realm = \"{1}\", nonce = \"{2}\", uri = \"{3}\", response = \"{4}\" \r\n\r\n", user, realm, nonce, uri, di_response);
                        this.status = OPTIONS2;
                    }
                    else
                    {
                        this.status = (this.session != null) ? PLAYING : (this.airplay2 ? PAIR_PIN_START : ANNOUNCE);
                        if (this.status == ANNOUNCE) { emitPairSuccess?.Invoke(); };
                    }
                    break;
                case OPTIONS2:
                    /*
                     * Devices like Apple TV and Zeppelin Air do not support encryption.
                     * Only way of checking that: they do not reply to Apple-Challenge
                     */
                    // if(headers["Apple-Response"])
                    //   this.requireEncryption = true;
                    this.status = (this.session != null) ? PLAYING : (this.airplay2 ? SETUP_AP2_1 : ANNOUNCE);
                    if (this.status == ANNOUNCE) { emitPairSuccess?.Invoke(); };
                    break;
                case ANNOUNCE:
                    this.status = SETUP;
                    break;
                case SETUP:
                    this.status = RECORD;
                    this.session = headerDict["Session"];
                    this.parsePorts(headerDict);
                    break;
                case RECORD:
                    if (!this.airplay2)
                    {
                        this.session = this.session ?? "1";
                        emitReady?.Invoke();
                    };
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
