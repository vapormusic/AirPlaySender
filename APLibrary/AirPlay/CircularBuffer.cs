using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay
{
    public class CircularBuffer
    {
        private int WAITING = 0,
        FILLING = 1,
        NORMAL = 2,
        DRAINING = 3,
        ENDING = 4,
        ENDED = 5;
        private int maxSize;
        private int packetSize;
        private bool writable;
        private bool muted = false;
        private List<byte[]> buffers;
        private int currentSize;
        private int status;
        private PacketPool packetPool;

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
                // this.emit('status','buffering')
                this.status = FILLING;
            }
            
            if (this.status == FILLING && this.currentSize > this.maxSize / 2)
            {
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
            if (this.status != ENDING && this.status != ENDED && (this.status == FILLING || this.currentSize < this.packetSize))
            {
                Array.Clear(packet.data, 0, packet.data.Length);

                if (this.status != FILLING && this.status != WAITING)
                {
                    this.status = FILLING;
                    //this.emit('status', 'buffering');
                }
            }
            else
            {
                int offset = 0;
                int remaining = this.packetSize;
                while (remaining > 0)
                {
                    // pad packet with silence if buffer is empty
                    if (this.buffers.Count == 0)
                    {
                        Array.Clear(packet.data, offset, packet.data.Length - offset);
                        remaining = 0;
                        break;
                    }

                    var first = this.buffers[0];
                    
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
                        Array.Copy(first, 0, packet.data, offset, remaining - first.Length);
                        this.buffers[0] = first.Skip(remaining).ToArray();
                        remaining = 0;
                        offset += remaining;
                    }
                }
                
                this.currentSize -= this.packetSize;

                if (this.status == ENDING && this.currentSize <= 0)
                {
                    this.status = ENDED;
                    this.currentSize = 0;
                    // this.emit('status','end')

                }
                
                if (this.status == DRAINING && this.currentSize < this.maxSize / 2)
                {
                    this.status = NORMAL;
                    // this.emit('drain');
                }
            }
            
            if (this.muted)
            {
                Array.Clear(packet.data, 0, packet.data.Length);
            }

            
            return packet;
        }
    }
}
