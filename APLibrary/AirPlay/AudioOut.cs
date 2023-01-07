using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace APLibrary.AirPlay
{
    public delegate void PacketEvent(Packet packet);
    public delegate void NeedSyncEvent(long seq);
    public class AudioOut
    {
        public long lastSeq;
        private bool hasAirTunes;
        private long rtp_time_ref;
        private static long SEQ_NUM_WRAP = (long) Math.Pow(2, 16);
        public AirTunesDevice device;

        public event PacketEvent emitPacket;
        public event NeedSyncEvent emitNeedSync;

        public AudioOut()
        {
             lastSeq = -1;
             hasAirTunes = false;
        }
        
        public void Init(Devices devices, CircularBuffer circularBuffer)
        {
            rtp_time_ref = (long) (DateTimeOffset.Now.ToUnixTimeMilliseconds());

            void listener1(bool hasAirTunes)
            {
                this.hasAirTunes = hasAirTunes;
            }

            void listener2()
            {
                emitNeedSync?.Invoke(this.lastSeq);
            }
            
            devices.emitAirTunesDevices += listener1;
            // A sync is forced when a new remote device is added.
            devices.emitDevicesNeedSync += listener2;
            
            void SendPacket(long seq)
            {
                
                var packet = circularBuffer.ReadPacket();
                packet.seq = seq % SEQ_NUM_WRAP;
                packet.timestamp = (seq * 352 + 2 * 44100) % 4294967296;

                if (hasAirTunes && (seq % 126 == 0))
                {
                    emitNeedSync?.Invoke(seq);
                }

                emitPacket?.Invoke(packet);
                packet.Release();
            }

            void SyncAudio()
            {

                /*
                 * Each time syncAudio() runs, a burst of packet is sent.
                 * Increasing config.stream_latency lowers CPU usage but increases the size of the burst.
                 * If the burst size exceeds the UDP windows size (which we do not know), packets are lost.
                 */
                // Debug.WriteLine("ref: " + rtp_time_ref.ToString());
                var elapsed = DateTimeOffset.Now.ToUnixTimeMilliseconds() - rtp_time_ref;
                /*
                 * currentSeq is the # of the packet we should be sending now. We have some packets to catch-up
                 * since syncAudio is not always running.
                 */
                long currentSeq = (long)(decimal)(elapsed * 44100) / (352 * 1000);

                for (long i = this.lastSeq + 1; i <= currentSeq; i++)
                    SendPacket(i);
                this.lastSeq = currentSeq;

                // reschedule ourselves later
                
                SetTimeout(SyncAudio,1);
            }

            SyncAudio();
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
    }
}


