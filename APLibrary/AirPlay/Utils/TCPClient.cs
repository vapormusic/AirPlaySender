using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace APLibrary.AirPlay.Utils
{
    using System;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using TcpClient = NetCoreServer.TcpClient;

    namespace TcpChatClient
    {
        class SimpleTCPClient : TcpClient
        {
            public SimpleTCPClient(string address, int port) : base(address, port) { }

            public void DisconnectAndStop()
            {
                _stop = true;
                DisconnectAsync();
                while (IsConnected)
                    Thread.Yield();
            }

            protected override void OnConnected()
            {
            }

            protected override void OnDisconnected()
            {
            }

            protected override void OnReceived(byte[] buffer, long offset, long size)
            {
                //Console.WriteLine(Encoding.UTF8.GetString(buffer, (int)offset, (int)size));
            }

            protected override void OnError(SocketError error)
            {
            }

            private bool _stop;
            }
        }
    }
