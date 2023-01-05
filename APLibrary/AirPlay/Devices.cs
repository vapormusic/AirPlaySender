using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using APLibrary.AirPlay.Types;

namespace APLibrary.AirPlay
{
    public delegate void AirTunesDevicesEvent(bool hasAirTunes);
    public delegate void DevicesNeedSyncEvent();
    public delegate void DevicesStatusEvent(string key, string status, string desc);
    public class Devices
    {
        public IDictionary<string, AirTunesDevice> devices;
        public bool hasAirTunes;
        public AudioOut audioOut;
        public string status;
        public event AirTunesDevicesEvent emitAirTunesDevices;
        public event DevicesNeedSyncEvent emitDevicesNeedSync;
        public event DevicesStatusEvent emitDevicesStatus;
        //public source

        public Devices(AudioOut audioOut)
        {

            //this.source = null;
            this.devices = new Dictionary<string, AirTunesDevice>();
            this.hasAirTunes = false;
            this.audioOut = audioOut;
            
        }

        private void NeedSyncHandler(long seq) {
            foreach(KeyValuePair<string, AirTunesDevice> kvp in this.devices)
            {
                if (!this.devices.ContainsKey(kvp.Key))
                  continue;

                if (kvp.Value.onSyncNeeded != null && kvp.Value.controlPort != null)
                    kvp.Value.onSyncNeeded(seq);
             }
        }

        public void Init()
        {
                    this.audioOut.emitNeedSync += NeedSyncHandler;
        }

         public AirTunesDevice add(string type, string host, AirTunesOptions options)
         {

            this.status = "connecting";
            var dev =
              // type === 'coreaudio' ?
              //   new CoreAudioDevice(this.hasAirTunes, this.audioOut, options) :
              new AirTunesDevice(host, this.audioOut, options, options?.mode ?? 0, (options?.txt) ?? new string[0]);

            

            if (this.devices.ContainsKey(dev.key))
            {
                var previousDev = this.devices[dev.key];
                // if device is already in the pool, just report its existing status.
                previousDev.reportStatus();

                return previousDev;
            }
            
            this.devices[dev.key] = dev;

            void x(string status)
            {
                if (status == "error" || status == "stopped")
                {
                    this.devices.Remove(dev.key);
                    checkAirTunesDevices();
                }

                if (this.hasAirTunes && status == "playing")
                {
                    emitDevicesNeedSync.Invoke();
                }
            };
            
            dev.emitDeviceStatus += x;



            dev.Start();
            checkAirTunesDevices();

            return dev;
         }
        
         public void setVolume(string key, int volume, Action callback)
         {
            var dev = this.devices[key];

            if (dev == null)
            {
                emitDevicesStatus?.Invoke(key, "error", "not_found");

                return;
            }

            dev.setVolume(volume, callback);
         }

         public void setProgress(string key, int progress, int duration, Action callback)
         {
            var dev = this.devices[key];

            if (dev == null)
            {
                emitDevicesStatus?.Invoke(key, "error", "not_found");

                return;
            }

            dev.setProgress(progress, duration, callback);
         }

         public void setTrackInfo(string key, string name, string artist, string album, Action callback)
         {
            var dev = this.devices[key];

            if (dev == null)
            {
                emitDevicesStatus?.Invoke(key, "error", "not_found");

                return;
            }

            dev.setTrackInfo(name, artist, album, callback);
         }

         public void setArtwork(string key, byte[] art, string contentType, Action callback)
         {
            var dev = this.devices[key];

            if (dev == null)
            {
                emitDevicesStatus?.Invoke(key, "error", "not_found");

                return;
            }

            dev.setArtwork(art, contentType, callback);
         }

         public void setPasscode(string key, string passcode)
         {
            var dev = this.devices[key];

            if (dev == null)
            {
                emitDevicesStatus?.Invoke(key, "error", "not_found");

                return;
            }

            dev.setPasscode(passcode);
         }

         public void stopAll(Action allCb)
         {
            // conver to array to make async happy
            foreach (KeyValuePair<string, AirTunesDevice> kvp in this.devices)
            {
                if (!this.devices.ContainsKey(kvp.Key))
                    continue;

                kvp.Value.stop(allCb);
                

            }

            this.devices = new Dictionary<string, AirTunesDevice>();

         }

         public void checkAirTunesDevices()
         {
            bool newHasAirTunes = false;

            foreach (KeyValuePair<string, AirTunesDevice> kvp in this.devices)
            {
                if (!this.devices.ContainsKey(kvp.Key))
                    continue;

                AirTunesDevice device = this.devices[kvp.Key];

                if (device.type == "airtunes")
                {
                    newHasAirTunes = true;
                    break;
                }
            }

            if (newHasAirTunes != this.hasAirTunes)
            {
                emitAirTunesDevices?.Invoke(newHasAirTunes);

                foreach (KeyValuePair<string, AirTunesDevice> kvp in this.devices)
                {
                    if (!this.devices.ContainsKey(kvp.Key))
                        continue;

                    //if (kvp.Value.onSyncNeeded != null && kvp.Value.controlPort != null)
                    //    kvp.Value.onSyncNeeded((int)seq);

                    //if (kvp.Value.setHasAirTunes != null)
                    //    kvp.Value.setHasAirTunes(newHasAirTunes);
                }
            }

            this.hasAirTunes = newHasAirTunes;
        }

    }
}
