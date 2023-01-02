using APLibrary.AirPlay;
using static System.Net.Mime.MediaTypeNames;
using System.Net.Mime;
using System.Xml.Linq;
using System;
using APLibrary.AirPlay.Types;

namespace APLibrary
{
    public delegate void APClientStatus(string status, string? key = null, string msg = "", string desc = "");
    public class AirPlayClient
    {
        public Devices devices;
        public bool writable;
        public APClientStatus? APClientEvent;
        public CircularBuffer circularBuffer;
        

        public AirPlayClient()
        {

            var audioOut = new AudioOut();
            this.devices = new Devices(audioOut);

            this.devices.Init();
            this.devices.emitDevicesStatus += Devices_emitDevicesStatus;

            this.circularBuffer = new CircularBuffer(200, 352 * 2 * 2);
            this.circularBuffer.emitBufferStatus += CircularBuffer_emitBufferStatus;


            audioOut.Init(this.devices, this.circularBuffer);



            this.writable = true;
        }

        private void Devices_emitDevicesStatus(string key, string status, string desc)
        {
            APClientEvent?.Invoke("status", key, status, desc);
        }

        private void CircularBuffer_emitBufferStatus(string status)
        {
            APClientEvent?.Invoke("buffer_status", status);
        }


        public AirTunesDevice add(string host, AirTunesOptions options)
        {
            return this.devices.add("airtunes", host, options);
        }

        public void stopAll(Action cb)
        {
            this.devices.stopAll(cb);
        }

        public void setVolume(string deviceKey, int volume, Action callback)
        {
            this.devices.setVolume(deviceKey, volume, callback);
        }

        public void setProgress(string deviceKey, int progress, int duration, Action callback)
        {
            this.devices.setProgress(deviceKey, progress, duration, callback);
        }

        public void setTrackInfo(string deviceKey, string name, string artist, string album, Action callback)
        {
            this.devices.setTrackInfo(deviceKey, name, artist, album, callback);
        }

        public void reset()
        {
            this.circularBuffer.Reset();
        }

        public void setArtwork(string deviceKey, byte[] art, string contentType, Action callback)
        {
            this.devices.setArtwork(deviceKey, art, contentType, callback);
        }

        public bool write(byte[] data)
        {
            return this.circularBuffer.Write(data);
        }

        public void setPasscode(string deviceKey, string passcode)
        {
            this.devices.setPasscode(deviceKey, passcode);
        }

        public void end()
        {
            this.circularBuffer.End();
        }

    }
}