using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace APLibrary.AirPlay
{
    public delegate void BufferStatusEvent(string status);
    public class CircularBuffer
    {
        private int WAITING = 0,
        FILLING = 1,
        NORMAL = 2,
        DRAINING = 3,
        ENDING = 4,
        ENDED = 5;
        private long maxSize;
        private int packetSize;
        private bool writable;
        private bool muted = false;
        private List<byte[]> buffers;
        private long currentSize;
        private int status;
        private PacketPool packetPool;
        public BufferStatusEvent? emitBufferStatus;

        public CircularBuffer(int packetsInBuffer, int size)
        {
            packetPool = new PacketPool();
            maxSize = packetsInBuffer * size;
            packetSize = size;
            buffers = new List<byte[]>();
            status = WAITING;
            currentSize = 0;
            writable = true;
            muted = false;
        }

        public bool Write(byte[] chunk)
        {
            this.buffers.Add(chunk);
            this.currentSize += chunk.Length;
            
            if (this.status == ENDING || this.status == ENDED)
            {
                throw new Exception("Cannot write in buffer after closing it");
            }   
            
            if (this.status == WAITING)
            {
                emitBufferStatus?.Invoke("buffering");
                Debug.WriteLine("BufferBuffering");
                // this.emit('status','buffering')
                this.status = FILLING;
            }
            
            if (this.status == FILLING && this.currentSize > this.maxSize / 2)
            {
                emitBufferStatus?.Invoke("playing");
                Debug.WriteLine("BufferPlaying");
                // this.emit('status','playing')
                this.status = NORMAL;
            }

            if (this.currentSize >= this.maxSize)
            {
                this.status = DRAINING;
                return false;
            }
            else
            {
                return true;
            }

        }

        public Packet ReadPacket()
        {
            Packet packet = this.packetPool.GetPacket();
            // play silence until buffer is filled enough
            if (this.status != ENDING && this.status != ENDED 
                && (this.status == FILLING || this.currentSize < this.packetSize))
            {
                packet.data = new byte[packet.data.Length];

                if (this.status != FILLING && this.status != WAITING)
                {
                    this.status = FILLING;
                    emitBufferStatus?.Invoke("buffering");
                    //this.emit('status', 'buffering');
                }
            }
            else
            {
                long offset = 0;
                long remaining = this.packetSize;
                while (remaining > 0)
                {
                    // pad packet with silence if buffer is empty
                    if (this.buffers.Count == 0)
                    {
                        Array.Clear(packet.data, 0, packet.data.Length);
                        remaining = 0;
                        break;
                    }

                    byte[] first = this.buffers[0];
                    
                    if (first.Length <= remaining)
                    {
                        // pop the whole buffer from the queue
                        Array.Copy(first, 0, packet.data, offset, first.Length);
                        offset += first.Length;
                        remaining -= first.Length;
                        this.buffers.RemoveAt(0);
                    }
                    else
                    {
                        // first buffer contains enough data to fill a packet: slice it
                        Array.Copy(first, 0, packet.data, offset, remaining);
                        this.buffers[0] = new byte[first.Length - remaining];

                        System.Buffer.BlockCopy(first,(int) remaining, this.buffers[0], 0, this.buffers[0].Length);
                        offset += offset + remaining;
                        remaining = 0;
                    }
                }
                
                this.currentSize -= this.packetSize;

                if (this.status == ENDING && this.currentSize <= 0)
                {
                    this.status = ENDED;
                    this.currentSize = 0;
                    emitBufferStatus?.Invoke("end");
                    // this.emit('status','end')

                }
                
                if (this.status == DRAINING && this.currentSize < this.maxSize / 2)
                {
                    this.status = NORMAL;
                    emitBufferStatus?.Invoke("drain");
                    // this.emit('drain');
                }
            }
            
            if (this.muted)
            {
                packet.data = new byte[packet.data.Length];
            }

            
            return packet;
        }

        public void End()
        {
            // flush the buffer if it was filling
            if (this.status == FILLING)
                emitBufferStatus?.Invoke("playing");

            this.status = ENDING;
        }

        public void Reset()
        {
            this.buffers = new List<byte[]>();
            this.currentSize = 0;
            this.status = WAITING;
        }

    }
}
