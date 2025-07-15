
using NICDevice.Core;
using NICDevice.Interfaces;
using NICDevice.IP;
using NICDevice.Layers;
using NICDevice.MAC;
using SharpPcap;
using System.Text;

namespace project_test
{
    public class IGMPv2 : NIC, ILayer
    {
        public byte[] LayerBytes { get; set; }
        public IPAddress multicastIPAddress { get; private set; }
        public  MacAddress multicastMacAddress { get; private set; }
        public MacAddress MacAddress { get; set; } 
        public IPAddress IPAddress { get; set; }
        private bool __is_running = false;
        
        public void Join(IPAddress multicastIPAddress, short QueryType)
        {
          
            
            this.SendPacket(new EthernetLayer(multicastMacAddress = IPv4MulticastToMac(multicastIp: multicastIPAddress), SystemMacAddress, 0x800),
                new IPV4Layer(SystemProtocolAddress, this.multicastIPAddress=multicastIPAddress, 0x2/*IGMP*/, 3, this.Payload()));
            if(!__is_running)
            {
                __is_running = true;
                if(!CaptureDevice.Started)
                {
                    CaptureDevice.Open();
                }
                CaptureDevice.OnPacketArrival += MulticastListener;
                CaptureDevice.StartCapture();
            }
        }
        public void SendSimpleAscii(string message)
        {
          
            short oursimpleProtocol = 0x2322;
            SendPacket(new EthernetLayer(multicastMacAddress,SystemMacAddress, oursimpleProtocol),new SimpleAsciiProtocol(message));
        }
        public static MacAddress IPv4MulticastToMac(IPAddress multicastIp)
        {
            var ipBytes = multicastIp.IPAddressBytes;

            if (ipBytes[0] < 224 || ipBytes[0] > 239)
                throw new ArgumentException("Not a multicast IP address");

            // Lower 23 bits of the IP address
            byte[] macBytes = new byte[6];
            macBytes[0] = 0x01;
            macBytes[1] = 0x00;
            macBytes[2] = 0x5E;
            macBytes[3] = (byte)(ipBytes[1] & 0x7F); // Mask high bit
            macBytes[4] = ipBytes[2];
            macBytes[5] = ipBytes[3];

            return new MacAddress(macBytes);
        }

        private void MulticastListener(object sender, SharpPcap.PacketCapture e)
        {
            var packet = e.GetPacket().Data;
            if(packet.Length<12)//src and des mac len check
                return;
            if (packet[12..14].SequenceEqual<byte>([0x23,0x22]))
            {
                if(packet[..6].SequenceEqual(multicastMacAddress.MacAddressBytes) && !packet[6..12].SequenceEqual<byte>(MacAddress.MacAddressBytes))
                {
                    var GotDate = packet[12..];
                    Console.WriteLine($"Byte Recv->String {Encoding.ASCII.GetString(GotDate)}");
                }
               
            }
        }

   
        public  void Leave()
        {
            if(__is_running)
                __is_running = false;
            CaptureDevice.OnPacketArrival -= MulticastListener;
        }
        private bool isCheckSumCalculated = false;
        public byte[] Payload()
        {
            
                LayerBytes ??= [

                     0b00010010, // Type (e.g., 0x12) – make sure this matches your protocol
                     0b00000010, // Max Response Time (e.g., 0x02)
                     0x00,       // Checksum high byte (placeholder)
                     0x00,       // Checksum low byte (placeholder)
                     ..multicastIPAddress.IPAddressBytes

                     ];

                if (!isCheckSumCalculated)
                {
                    // Calculate checksum over the whole IGMP message
                    ushort checksum = IPV4Layer.CalculateChecksum(LayerBytes);

                    // Insert checksum into bytes [2] and [3] in big-endian order
                    LayerBytes[2] = (byte)(checksum >> 8);
                    LayerBytes[3] = (byte)(checksum & 0xFF);

                    isCheckSumCalculated = true;
                }

                return LayerBytes;
           
        }

    }
}
