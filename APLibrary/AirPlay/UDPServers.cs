using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.Intrinsics.Arm;
using System.Text;
using System.Threading;
using APLibrary.AirPlay;
using APLibrary.AirPlay.Utils;
using BitConverter;
using NetCoreServer;
using SecureRemotePassword;
using NetCoreServer;
using System.Diagnostics;


namespace AirPlayClient
{

        public class EchoServer : UdpServer
        {
        public NTP ntp = new NTP();
        public EchoServer(IPAddress address, int port) : base(address, port) {

        }

        protected override void OnStarted()
        {
            // Start receive datagrams
            ReceiveAsync();
        }

        protected override void OnReceived(EndPoint endpoint, byte[] buffer, long offset, long size)
        {
            // read the data

            uint ts1 = EndianBitConverter.BigEndian.ToUInt32(buffer, 24);
            uint ts2 = EndianBitConverter.BigEndian.ToUInt32(buffer, 28);

            byte[] reply = new byte[32];
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80d3), 0, reply, 0, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x0007), 0, reply, 2, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)0x00000000), 0, reply, 4, 4);

            Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts1), 0, reply, 8, 4);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts2), 0, reply, 12, 4);

            Array.Copy(ntp.getNTPTimestamp(), 0, reply, 16, 8);
            Array.Copy(ntp.getNTPTimestamp(), 0, reply, 24, 8);
            // Echo the message back to the sender
            SendAsync(endpoint, reply, 0, reply.Length);
        }

        protected override void OnSent(EndPoint endpoint, long sent)
        {
            // Continue receive datagrams
            ReceiveAsync();
        }

        protected override void OnError(SocketError error)
        {
            Debug.WriteLine($"Echo UDP server caught an error with code {error}");
        }
    }
    
    public class UDPServers
    {
        // Create the two sockets.
        public EchoServer timingSocket;
        public Socket controlSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        


        // Create a byte array to hold the received data.

        public IPEndPoint timingEndPoint;
        public EndPoint controlEndPoint;
        public IPEndPoint? anyIP;
        public UDPServers()
        {
            timingEndPoint = new IPEndPoint(LocalIPAddress(), 0);
            controlEndPoint = new IPEndPoint(LocalIPAddress(), 0);
            

        }

        public void bind(string host) {

            controlSocket.Bind(controlEndPoint);
            timingSocket = new EchoServer(IPAddress.Any, 17459);

            // Start the server
            Console.Write("Server starting...");
            timingSocket.Start();
        }
        
        private void recv(IAsyncResult res)
        {
            //Debug.WriteLine("SSDK SDSC 2");
            //byte[] dataBuffer = timingSocket._socket.EndReceive(res);
            
            //// read the data
            
            //uint ts1 = EndianBitConverter.BigEndian.ToUInt32(dataBuffer, 24);
            //uint ts2 = EndianBitConverter.BigEndian.ToUInt32(dataBuffer, 28);

            //byte[] reply = new byte[32];
            //Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80d3), 0, reply, 0, 2);
            //Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x0007), 0, reply, 2, 2);
            //Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)0x00000000), 0, reply, 4, 4);

            //Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts1), 0, reply, 8, 4);
            //Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts2), 0, reply, 12, 4);

            //Array.Copy(ntp.getNTPTimestamp(), 0, reply, 16, 8);
            //Array.Copy(ntp.getNTPTimestamp(), 0, reply, 24, 8);

            //timingSocket.Send(reply);
            //timingSocket.BeginReceive(new AsyncCallback(recv), null);
        }
        
        public void ReadTimestamp()
        {
                
                //byte[] dataBuffer = new byte[1024];
                //int v = controlSocket.ReceiveFrom(dataBuffer, ref anyIP);
                //Debug.WriteLine("HMM2");

                //// read the data

                //uint ts1 = EndianBitConverter.BigEndian.ToUInt32(dataBuffer, 24);
                //uint ts2 = EndianBitConverter.BigEndian.ToUInt32(dataBuffer, 28);

                //byte[] reply = new byte[32];
                //Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80d3), 0, reply, 0, 2);
                //Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x0007), 0, reply, 2, 2);
                //Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)0x00000000), 0, reply, 4, 4);

                //Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts1), 0, reply, 8, 4);
                //Array.Copy(EndianBitConverter.BigEndian.GetBytes(ts2), 0, reply, 12, 4);

                //Array.Copy(ntp.getNTPTimestamp(), 0, reply, 16, 8);
                //Array.Copy(ntp.getNTPTimestamp(), 0, reply, 24, 8);

                //timingSocket.Send(reply, anyIP);

        }

        public void ReceiveControlData()
        {

                //Debug.WriteLine("HMM");
                //byte[] dataBuffer = new byte[1024];
                //// Receive data on the control socket and store it in the data buffer.
                //int v = controlSocket.ReceiveFrom(dataBuffer, ref anyIP);


                //// TODO: Read the second, fifth, and eighth values from the data buffer and
                //// interpret them as unsigned 8-bit and 16-bit integers in low-endian and
                //// big-endian formats, respectively.

                //if (dataBuffer[1] == (0x80 | 0x55))
                //{
                //    ushort serverSeq = EndianBitConverter.BigEndian.ToUInt16(dataBuffer, 2);
                //    ushort missedSeq = EndianBitConverter.BigEndian.ToUInt16(dataBuffer, 4);
                //    ushort count = EndianBitConverter.BigEndian.ToUInt16(dataBuffer, 6);
                //    //self.emit('resendRequested', missedSeq, count)
                //}
        }

        public void SendControlSync(AirTunesDevice device, long seq)
        {
            byte[] data = new byte[20];
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x80d4), 0, data, 0, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((ushort)0x0007), 0, data, 2, 2);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)((seq * 352) % 4294967296)), 0, data, 4, 4);
            Array.Copy(timingSocket.ntp.getNTPTimestamp(), 0, data, 8, 8);
            Array.Copy(EndianBitConverter.BigEndian.GetBytes((uint)((seq * 352 + 2 * 44100) % 4294967296)), 0, data, 16, 4);
            EndPoint remoteSendEndPoint = new IPEndPoint(IPAddress.Parse(device.host), device.port);
            controlSocket.SendTo(data, remoteSendEndPoint);
        }

        public void Close()
        {
            // Close the sockets.
            timingSocket.Stop();
            controlSocket.Close();

        }

        private IPAddress LocalIPAddress()
        {
            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
            {
                return null;
            }

            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

            return host
                .AddressList
                .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        }
    }
}