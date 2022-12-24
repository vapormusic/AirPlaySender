﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay
{
    public delegate void PacketEvent(Packet packet);
    public delegate void NeedSyncEvent(int seq);
    public class AudioOut
    {
        private int lastSeq;
        private bool hasAirTunes;
        private int rtp_time_ref;
        private static int SEQ_NUM_WRAP = (int) Math.Pow(2, 16);

        public event PacketEvent emitPacket;
        public event NeedSyncEvent emitNeedSync;

        public AudioOut()
        {
             lastSeq = -1;
             hasAirTunes = false;
        }
        
        public void Init(Devices devices, CircularBuffer circularBuffer)
        {
            rtp_time_ref = (int) Math.Floor((double) (DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond));

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
            
            void SendPacket(int seq)
            {
                var packet = circularBuffer.ReadPacket();

                packet.seq = seq % SEQ_NUM_WRAP;
                packet.timestamp = (seq * 352 + 2 * 44100) % 4294967296;

                if (hasAirTunes && seq % 126 == 0)
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
                var elapsed = (int) Math.Floor((double)(DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond))- rtp_time_ref;

                /*
                 * currentSeq is the # of the packet we should be sending now. We have some packets to catch-up
                 * since syncAudio is not always running.
                 */
                int currentSeq = (int) Math.Floor((decimal) elapsed * 44100 / (352 * 1000));

                for (var i = this.lastSeq + 1; i <= currentSeq; i++)
                    SendPacket(i);

                lastSeq = currentSeq;

                // reschedule ourselves later
                SetTimeout(SyncAudio, 30);
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


