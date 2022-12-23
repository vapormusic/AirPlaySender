using AirPlayClient;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay
{
    public class AirTunesDevice
    {
        private UDPServers udpServers;
        private AudioOut audioOut;
        private string type = "airtunes";
        public string host;
        public int port;
        private string key;
        private int mode;
        private string[] statusflags;
        private bool alacEncoding;
        private string txt;
        private bool needPassword;
        private string needPin;
        private Socket audioSocket;

        public AirTunesDevice(string host, AudioOut audioOut, Options options, int mode = 0, string txt = "")
        {
            
            this.udpServers = new UDPServers();
            this.audioOut = audioOut;
            this.host = host;
            this.port = options.port || 5000;
            this.key = this.host + ':' + this.port;
            this.mode = mode; // Homepods with or without passcode
                              // if(options.password != null && legacy == true){
                              // this.mode = 1; // Airport / Shairport legacy passcode mode
                              // this.mode = 2 // MFi mode
                              // }
            this.statusflags = new string[] {};
            this.alacEncoding = options?.alacEncoding ?? true;
            this.txt = txt;
            //var transpiled = JsonConvert.DeserializeObject<T>(json);
            //let a = this.txt.filter((u) => String(u).startsWith('et='))
            //if ((a[0] ?? "").includes('4'))
            //            {
            //                this.mode = 2;
            //            }
            //            let b = this.txt.filter((u) => String(u).startsWith('cn='))
            //  if ((b[0] ?? "").includes('0'))
            //            {
            //                this.alacEncoding = false;
            //            }
            //            let c = this.txt.filter((u) => String(u).startsWith('sf='))
            //  this.statusflags = c[0] ? parseInt(c[0].substring(3)).toString(2).split('') : []
            //  if (c.length == 0)
            //            {
            //                c = this.txt.filter((u) => String(u).startsWith('flags='))
            //      this.statusflags = c[0] ? parseInt(c[0].substring(6)).toString(2).split('') : []
            //  }
            //this.needPassword = false;
            //this.needPin = false;
            //if (this.statusflags != [])
            //{
            //    let PasswordRequired = (this.statusflags[this.statusflags.length - 1 - 7] == '1')
            //  let PinRequired = (this.statusflags[this.statusflags.length - 1 - 3] == '1')
            //  let OneTimePairingRequired = (this.statusflags[this.statusflags.length - 1 - 9] == '1')
            //  console.log('needPss', PasswordRequired, PinRequired, OneTimePairingRequired)
            //  this.needPassword = (PasswordRequired || PinRequired || OneTimePairingRequired)
            //  this.needPin = (PinRequired || OneTimePairingRequired)
            //  console.log('needPss', this.needPassword)
            //}
            //console.log("needPin", this.needPin)
            //console.log("mode-atv", this.mode)
            //console.log("alacEncoding", this.alacEncoding)


            //this.rtsp = new RTSP.Client(options.volume || 50, options.password || null, audioOut,
            //    {
            //    mode: this.mode,
            //    txt: this.txt,
            //    alacEncoding: this.alacEncoding,
            //    needPassword: this.needPassword,
            //    needPin: this.needPin,
            //    debug: options.debug
            //  });
            //this.audioCallback = null;
            //this.encoder = [];
        }

        public void Start()
        {
            this.audioSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            this.udpServers.bind();
            this.doHandshake();
            
        }
        
        public void doHandshake()
        {
            //this.rtsp.on('config', function(setup) {
            //    self.audioLatency = setup.audioLatency;
            //    self.requireEncryption = setup.requireEncryption;
            //    self.serverPort = setup.server_port;
            //    self.controlPort = setup.control_port;
            //    self.timingPort = setup.timing_port;
            //});

            //this.rtsp.on('ready', function() {
            //    self.relayAudio();
            //});

            //this.rtsp.on('need_password', function() {
            //    self.emit('status', 'need_password');
            //});

            //this.rtsp.on('pair_failed', function() {
            //    self.emit('status', 'pair_failed');
            //});

            //this.rtsp.on('pair_success', function() {
            //    self.emit('status', 'pair_success');
            //});

            //this.rtsp.on('end', function(err) {
            //    console.log(err);
            //    self.cleanup();

            //    if (err !== 'stopped')
            //        self.emit(err);
            //});

            //this.rtsp.startHandshake(this.udpServers, this.host, this.port);
        }

        public void relayAudio()
        {
            //this.audioCallback = function(data) {
            //    self.encoder.push(data);
            //    if(self.encoder.length > 10) {
            //        self.encoder.shift();
            //    }
            //    self.rtsp.sendAudio(data);
            //};
            //this.audioOut.on('data', this.audioCallback);
        }

        public void onSyncNeeded() { 
        }
        
    }
}
