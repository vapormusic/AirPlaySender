using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.Intrinsics.Arm;
using System.Text;
using APLibrary.AirPlay;
using BitConverter;

namespace AirPlayClient
{
    public class UDPServers
    {
        // Create the two sockets.
        private Socket timingSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private Socket controlSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private NTP ntp = new NTP();


        // Create a byte array to hold the received data.

        public EndPoint timingEndPoint;
        public EndPoint controlEndPoint;
        public EndPoint anyIP;
        public UDPServers()
        {
            timingEndPoint = new IPEndPoint(IPAddress.Any, 0);
            controlEndPoint = new IPEndPoint(IPAddress.Any, 0);
            anyIP = new IPEndPoint(IPAddress.Any, 0);

        }

        public void bind() {

            // Bind the sockets to the local IP address and a random port.
            timingSocket.Bind(timingEndPoint);
            controlSocket.Bind(controlEndPoint);
        }

        public void ReadTimestamp()
        {
            byte[] dataBuffer = new byte[1024];
            int v = controlSocket.ReceiveFrom(dataBuffer, ref anyIP);
            

            
            // read the data

            uint ts1 = EndianBitConverter.BigEndian.ToUInt32(dataBuffer, 24);
            uint ts2 = EndianBitConverter.BigEndian.ToUInt32(dataBuffer, 28);

            byte[] reply = new byte[32];
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80d3), 0, reply, 0, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x0007), 0, reply, 2, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)0x00000000), 0, reply, 4, 4);

            Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts1), 0, reply, 8, 4);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts2), 0, reply, 12, 4);
         
            Array.Copy(ntp.getNTPTimestamp(), 0, reply, 16, 8);
            Array.Copy(ntp.getNTPTimestamp(), 0, reply, 24, 8);

            controlSocket.SendTo(reply, anyIP);

        }

        public void ReceiveControlData()
        {
            byte[] dataBuffer = new byte[1024];
            // Receive data on the control socket and store it in the data buffer.
            int v = controlSocket.ReceiveFrom(dataBuffer, ref anyIP);

            // TODO: Read the second, fifth, and eighth values from the data buffer and
            // interpret them as unsigned 8-bit and 16-bit integers in low-endian and
            // big-endian formats, respectively.

            if (dataBuffer[1] == (0x80 | 0x55))
            {
                ushort serverSeq = EndianBitConverter.BigEndian.ToUInt16(dataBuffer, 2);
                ushort missedSeq = EndianBitConverter.BigEndian.ToUInt16(dataBuffer, 4);
                ushort count = EndianBitConverter.BigEndian.ToUInt16(dataBuffer, 6);
                //self.emit('resendRequested', missedSeq, count)
            }
        }

        public void SendControlSync(AirTunesDevice device, int seq)
        {
            byte[] data = new byte[20];
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80d4), 0, data, 0, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x0007), 0, data, 2, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)((seq * 352) % 4294967296)), 0, data, 4, 4);
            Array.Copy(ntp.getNTPTimestamp(), 0, data, 8, 8);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)((seq * 352 + 2 * 44100) % 4294967296)), 0, data, 16, 4);
            EndPoint remoteSendEndPoint = new IPEndPoint(IPAddress.Parse(device.host), device.port);
            controlSocket.SendTo(data, remoteSendEndPoint);
        }
    }
}