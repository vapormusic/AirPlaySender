using AirPlayClient;
using APLibrary.AirPlay.HomeKit;
using APLibrary.AirPlay.Types;
using APLibrary.AirPlay.Utils;
using Claunia.PropertyList;
using Microsoft.VisualBasic;
using Newtonsoft.Json.Linq;
using SecureRemotePassword;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

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
        private byte[] pair_verify_1_verifier;
        private byte[] pair_verify_1_signature;
        private byte[] code_digest;
        private byte[] authSecret;
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
        private byte[] P;
        private byte[] s;
        private byte[] B;
        private byte[] A;
        private byte[] a;
        private byte[] Al;
        private byte[] M1;
        private byte[] epk;
        private byte[] authTag;
        private byte[] _atv_salt;
        private byte[] _atv_pub_key;
        private byte[] _hap_genkey;
        private byte[] _hap_encrypteddata;
        private string? pairingId;
        private byte[] seed ;
        private Credentials credentials;
        private byte[] event_credentials;
        private byte[] verifier_hap_1;
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

        public byte[]? ExecRequest(byte[] input ,bool GetResponse){
            if (this.encryptedChannel && this.credentials != null)
            {
                input = this.credentials.encrypt(input);
            }
            nsctrl.Write(input, 0, input.Length);

            if (!GetResponse)
                return null;

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
            return res;
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

        public void cleanup(string type, string msg)
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
            return this.makeHead(method, "rtsp://" + this.socket?.Client.LocalEndPoint.ToString() + "/" + this.announceId, digestInfo);
        }

        public void sendNextRequest(int? force_mode = null)
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
    
            }




            ExecRequest(request, getResponse);

        }
        
    }
}
