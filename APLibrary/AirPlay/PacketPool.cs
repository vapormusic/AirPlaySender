using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay
{
    public class Packet
    {
        public byte[] data;
        public int refr;
        public int seq;
        public long timestamp;
        private PacketPool pool;
        public Packet(PacketPool pool)
        {
            this.data = new byte[1408];
            this.refr = 1;
            this.seq = -1;
            this.pool = pool;
        }

        public void Retain()
        {
            this.refr++;
        }
        public void Release()
        {
            this.refr--;
            if (this.refr == 0)
            {
                this.seq = -1;
                this.pool.ReleasePacket(this);
            }
        }
    }

    
    public class PacketPool
    {
        private List<Packet> pool;
        public PacketPool()
        {
            pool = new List<Packet>();

        }

        public Packet GetPacket()
        {
            if (pool.Count > 0)
            {
                Packet p = pool[0];
                pool.RemoveAt(0);
                p.Retain();
                return p;
            }
            else
            {
                return new Packet(this);
            }

        }

        public void ReleasePacket(Packet p)
        {
            pool.Append(p);
        }

    }
    

    
}
