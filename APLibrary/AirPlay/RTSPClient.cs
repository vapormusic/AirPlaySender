using AirPlayClient;
using SecureRemotePassword;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace APLibrary.AirPlay
{
    public class RTSPClient
    {
        //TODO: write rtsp.js to c#
        private AudioOut audioOut;
        private int status;
        private Socket? socket;
        private int cseq;
        private string? announceId;
        private string? activeRemote;
        private string? dacpId;
        private string? session;
        private int? timeout;
        private int? volume;
        private int? progress;
        private int? duration;
        private int? starttime;
        private string password;
        private bool passwordTried;
        private bool requireEncryption;
        private string trackInfo;
        private byte[] artwork;
        private string artworkContentType;
        private Action callback;
        private int? controlPort;
        private int? timingPort;
        private int? timingDestPort;  
        private int? eventPort;
        private bool? heartBeat;
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
        private byte[] pairingId;
        private byte[] seed ;
        private byte[] credentials;
        private byte[] event_credentials;
        private byte[] verifier_hap_1;
        private byte[] encryptionKey;
        private bool encryptedChannel;
        private string hostip;
        private string homekitver;
        private int INFO = -1,
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

        public RTSPClient(int volume, string password, AudioOut audioOut, Options options)
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

        public void startHandshake (UDPServers udpServers, string host, string port)
        {
            var self = this;
            this.startTimeout();
            this.hostip = host;
            this.controlPort = ((IPEndPoint) udpServers.controlEndPoint).Port;
            this.timingPort = ((IPEndPoint)udpServers.timingEndPoint).Port;

            TcpClient client = new TcpClient();
            client.Connect(host, int.Parse(port));
            this.socket = client.GetStream();
            this.socket.ReadTimeout = 10000;
            this.socket.WriteTimeout = 10000;
            
            
            this.socket = net.connect(port, host, async function() {
                self.clearTimeout();

                if (self.needPassword)
                {
                    self.status = PAIR_PIN_START;
                    self.sendNextRequest();
                    self.startHeartBeat();
                }
                else
                {
                    if (self.mode != 2)
                    {
                        if (this.debug) console.log("AUTH_SETUP", "nah")
                      self.status = OPTIONS;
                        self.sendNextRequest();
                        self.startHeartBeat();
                    }
                    else
                    {
                        self.status = AUTH_SETUP;
                        if (this.debug) console.log("AUTH_SETUP", "yah")
                      self.sendNextRequest();
                        self.startHeartBeat();
                    }


                }
            });

            var blob = [];
            this.socket.on('data', function(data) {
                if (self.encryptedChannel)
                {
                    // if (self.debug != false) console.log("incoming", data)
                    data = self.credentials.decrypt(data)
                }
                self.clearTimeout();

                /*
                 * I wish I could use node's HTTP parser for this...
                 * I assume that all responses have empty bodies.
                 */
                var rawData = data
              data = data.toString();

                blob += data;
                var endIndex = blob.indexOf('\r\n\r\n');

                if (endIndex < 0)
                {
                    return;
                }

                endIndex += 4;

                blob = blob.substring(0, endIndex);
                self.processData(blob, rawData);

                blob = data.substring(endIndex);
            });

            this.socket.on('error', function(err) {
                self.socket = null;
                if (this.debug) console.log(err.code);
                if (err.code === 'ECONNREFUSED')
                {
                    if (this.debug) console.log('block');
                    self.cleanup('connection_refused');
                }
                else
                    self.cleanup('rtsp_socket', err.code);
            });

            this.socket.on('end', function() {
                if (self.debug) console.log('block2');
                self.cleanup('disconnected');
            });
        };

        private void startTimeout()
        {
            var self = this;
            this.timeout = setTimeout(function() {
                if (self.debug) console.log('timeout');
                self.cleanup('timeout');
            }, config.rtsp_timeout);
        };

        private void clearTimeout()
        {
            if (this.timeout !== null)
            {
                clearTimeout(this.timeout);
                this.timeout = null;
            }
        };

        Client.prototype.teardown = function()
        {
            if (this.status === CLOSED)
            {
                this.emit('end', 'stopped');
                return;
            }

            this.status = TEARDOWN;
            this.sendNextRequest();
        };

        Client.prototype.setVolume = function(volume, callback)
        {
            if (this.status !== PLAYING)
                return;

            this.volume = volume;
            this.callback = callback;
            this.status = SETVOLUME;
            this.sendNextRequest();
        };

        Client.prototype.setProgress = function(progress, duration, callback)
        {
            if (this.status !== PLAYING)
                return;
            this.progress = progress;
            this.duration = duration;
            this.callback = callback;
            this.status = SETPROGRESS;
            this.sendNextRequest();
        };

        Client.prototype.setPasscode = async function(passcode)
        {
            this.password = passcode;
            this.status = this.airplay2 ? PAIR_SETUP_1 : PAIR_PIN_SETUP_1;
            this.sendNextRequest();
        }

        Client.prototype.startHeartBeat = function()
        {
            var self = this;

            if (config.rtsp_heartbeat > 0)
            {
                this.heartBeat = setInterval(function() {
                    self.sendHeartBeat(function(){
                        //console.log('HeartBeat sent!');
                    });
                }, config.rtsp_heartbeat);
            }
        };

        Client.prototype.sendHeartBeat = function(callback)
        {
            if (this.status !== PLAYING)
                return;

            this.status = OPTIONS;
            this.callback = callback;
            this.sendNextRequest();
        };

        Client.prototype.setTrackInfo = function(name, artist, album, callback)
        {
            if (this.status !== PLAYING)
                return;
            if (name != this.trackInfo?.name || artist != this.trackInfo?.artist || album != this.trackInfo?.album)
            {
                this.starttime = this.audioOut.lastSeq * config.frames_per_packet + 2 * config.sampling_rate;
            }
            this.trackInfo = {
            name: name,
    artist: artist,
    album: album
            };
            this.status = SETDAAP;
            this.callback = callback;
            this.sendNextRequest();
        };

        Client.prototype.setArtwork = function(art, contentType, callback)
        {
            if (this.status !== PLAYING)
                return;

            if (typeof contentType == 'function')
            {
                callback = contentType;
                contentType = null;
            }

            if (typeof art == 'string')
            {
                var self = this;
                if (contentType === null)
                {
                    var ext = art.slice(-4);
                    if (ext == ".jpg" || ext == "jpeg")
                    {
                        contentType = "image/jpeg";
                    }
                    else if (ext == ".png")
                    {
                        contentType = "image/png";
                    }
                    else if (ext == ".gif")
                    {
                        contentType = "image/gif";
                    }
                    else
                    {
                        return self.cleanup('unknown_art_file_ext');
                    }
                }
                return fs.readFile(art, function(err, data) {
                    if (err !== null)
                    {
                        return self.cleanup('invalid_art_file');
                    }
                    self.setArtwork(data, contentType, callback);
                });
            }

            if (contentType === null)
                return this.cleanup('no_art_content_type');

            this.artworkContentType = contentType;
            this.artwork = art;
            this.status = SETART;
            this.callback = callback;
            this.sendNextRequest();
        };

        Client.prototype.nextCSeq = function()
        {
            this.cseq += 1;

            return this.cseq;
        };

        Client.prototype.cleanup = function(type, msg)
        {
            this.emit('end', type, msg);
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
            // this.password = null;
            this.removeAllListeners();

            if (this.timeout)
            {
                clearTimeout(this.timeout);
                this.timeout = null;
            }

            if (this.heartBeat)
            {
                clearInterval(this.heartBeat);
                this.heartBeat = null;
            }

            if (this.socket)
            {
                this.socket.destroy();
                this.socket = null;
            }
        };
    }
}
