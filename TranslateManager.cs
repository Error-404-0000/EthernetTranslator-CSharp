using NICDevice.Core;
using NICDevice.IP;
using NICDevice.MAC;
using NICDevice.Protocols;

namespace EthernetTranslator_CSharp
{

    public class TranslateManager : NIC
    {
        public readonly List<TranslatorRecord> TranslatorRecords = new List<TranslatorRecord>();
        public TranslateManager()
        {
            //Console.Write("Enter Mac Address : ");
            //while (!MacAddress.TryParse(TONICMac= Console.ReadLine(),out MacAddress mac))
            //{
            //    Console.Write("Enter Mac Address : ");

            //}
            if (CaptureDevice is null)
                throw new ArgumentNullException(nameof(CaptureDevice));
            CaptureDevice.OnPacketArrival += HandleTranslates;
            if (!CaptureDevice.Started)
                CaptureDevice.StartCapture();
        }
        public void CancelTranslator() => CaptureDevice.OnPacketArrival -= HandleTranslates;

        /// <summary>
        /// Generates a new unique ID for translator records, reusing expired IDs if available. If no expired IDs
        /// exist, it returns the next smallest positive integer ID.
        /// </summary>
        /// <returns>Returns a ushort representing the new unique ID.</returns>
        ushort NewIdCreate(MacAddress Macaddress = null)
        {
            if (TranslatorRecords.Count == 0)
            {
                Console.WriteLine("[DEBUG] Created a new Start Id of 0x0001");
                return 0x0001;
            }
            else
            {
                if (Macaddress is not null)
                {
                    if (TranslatorRecords.Any(x => x.OwnerMac.ToString() == Macaddress))
                    {
                        Console.WriteLine("[DEBUG] found an entry. reusing it");

                        return TranslatorRecords.FirstOrDefault(x => x.OwnerMac.ToString() == Macaddress)?.ID ?? NewIdCreate();
                    }
                }

                // Try to find the first expired record (older than 5 minutes)
                var expiredRecordIndex = TranslatorRecords.FindIndex(x => x.DateTime.AddMinutes(5) < DateTime.Now);

                if (expiredRecordIndex != -1)
                {
                    Console.WriteLine("[DEBUG] found an expired entry. reusing it");
                    var expiredRecord = TranslatorRecords[expiredRecordIndex];
                    TranslatorRecords.Remove(expiredRecord);
                    return expiredRecord.ID;
                }
                else
                {
                    // Return next available smallest positive integer ID
                    var usedIds = TranslatorRecords.Select(x => x.ID).ToHashSet();
                    for (ushort newId = 1; ; newId++)
                    {
                        if (!usedIds.Contains(newId))
                        {
                            Console.WriteLine($"[DEBUG] Created a new entry with Id {newId}");

                            return newId;
                        }
                    }
                }

            }
        }
        (MacAddress? Mac, ushort ID, IPAddress IP) FindIdOwner(ushort id)
        {
            var owner = TranslatorRecords.FirstOrDefault(x => x.ID == id && x.DateTime.AddMinutes(5) > DateTime.Now);
            if (owner is not null)
            {
                Console.WriteLine($"[DEBUG] OwerId was found with infomation : {owner}");
                owner.DateTime = DateTime.Now;
                return (owner.OwnerMac, (ushort)(owner.ID), owner.OwnerIPAddress);
            }
            else
                Console.WriteLine($"[DEBUG] OwerId not found with Id : {id}");
            return (null, 0, null);
        }
        //00:50:79:66:68:01
        private void HandleTranslates(object sender, SharpPcap.PacketCapture e)
        {
            if (translators.Count() == 0)
                return;
            var packet = e.GetPacket().Data;
            //checking if it is a ipv4 forward-to-desip
            if (packet[12..14].SequenceEqual<byte>([0x08, 0x00]) && packet.Length >= 33)
            {
                //if the des mac address does not match the NIC first 4 mac address bytes ;return;
                if (!packet[0..4].SequenceEqual(NIC.SystemMacAddress.MacAddressBytes[0..4])) return;
                IPAddress ip = new IPAddress(packet[30..34]);

                var index = BestSubnetMatch(ip);

                if (index >= 0)
                    ModifySourceIPV4ToDestinationIPV4(packet, index, ip);


                else ModifyDestinationIPV4ToSourceIPV4(packet, new IPAddress(packet[26..30]));
            }
            else if (packet[12..14].SequenceEqual<byte>([0x08, 0x06]) && packet.Length >= 27)
            {
                CreateNewSessionViaARPReply(packet);
            }
        }
        //  private ARP externalArp = new ARP(NIC.DefaultGateWay,1,NIC.BroadCastMacAddress);
        const string TONICMac = "A2:15:07:3B:BE:1D";
        //static  string TONICMac;
        /// <summary>
        /// Translates the source IP address of a packet to a new destination IP address based on the specified index. 
        /// Example : 10.0.0.99/32 -> 10.0.0.1
        /// </summary>
        /// <param name="packet">The byte array representing the network packet that will be modified.</param>
        /// <param name="index">Specifies which translation to use for determining the new destination IP address.</param>
        /// <param name="ip">Represents the original IP address that is being translated to a new destination.</param>
        private void ModifySourceIPV4ToDestinationIPV4(byte[] packet, int index, IPAddress ip)
        {
            if (packet[12..14].SequenceEqual<byte>([0x08, 0x00]) && packet.Length >= 33)
            {

                if (index >= 0)
                {
                    var newIp = translators[index].TranslateTo.IPAddressBytes;

                    MacAddress router_mac = (MacAddress)TONICMac;
                    //saves the original id ,taken from the packet destination Mac 
                    //Example: Target Sends packet to  Destination Mac 00:50:79:66:00:01 set by ARP 
                    //So we extract the last 2 bytes of the destination mac address and set it to the id in this exampe it is 0x0001 or 1
                    ushort Id_ = (ushort)((packet[4] << 8) | packet[5]);

                    //we are reformatting the packet to look like it came from our device and sending it to the translator "To" IPAddress
                    packet[0] = router_mac[0];
                    packet[1] = router_mac[1];
                    packet[2] = router_mac[2];
                    packet[3] = router_mac[3];
                    packet[4] = router_mac[4];
                    packet[5] = router_mac[5];

                    MacAddress system_mac = (MacAddress)SystemMacAddress;

                    var Id = NewIdCreate(new MacAddress(packet[6..12]));
                    TranslatorRecords.Add(new TranslatorRecord(DateTime.Now, Id, new MacAddress(packet[6..12]), new IPAddress(packet[26..30])));
                    //We are setting the source mac address to our device mac address so the "To" device can reply to us directly
                    packet[6] = system_mac[0];
                    packet[7] = system_mac[1];
                    packet[8] = system_mac[2];
                    packet[9] = system_mac[3];
                    //EDITING THE SRC IP MAKING IT LOOK LIKE IT CAME FROM OUR DEVICE ON THE DES DEVICE
                    packet[26] = SystemProtocolAddress[0];
                    packet[27] = SystemProtocolAddress[1];
                    packet[28] = SystemProtocolAddress[2];
                    packet[29] = (byte)new Random().Next(0, 255);

                    //we are setting the last src mac address bytes to the id we created so we can track the owner packet via response later on
                    packet[10] = (byte)(Id >> 8);
                    packet[11] = (byte)(Id);
                    //we are setting the "To" IPaddress via the translator (redirecting)
                    packet[30] = newIp[0];
                    packet[31] = newIp[1];
                    packet[32] = newIp[2];
                    packet[33] = newIp[3];
                    packet[24] = 0;
                    packet[25] = 0;
                    int ipOffset = 14;

                    // ✅ Step 1: Clear IP checksum field
                    packet[ipOffset + 10] = 0;
                    packet[ipOffset + 11] = 0;

                    // ✅ Step 2: Recalculate and insert IP checksum
                    ushort newIpChecksum = CalculateIpChecksum(packet, ipOffset);
                    packet[ipOffset + 10] = (byte)(newIpChecksum >> 8);
                    packet[ipOffset + 11] = (byte)(newIpChecksum & 0xFF);

                    // ✅ Step 3: Only recalculate TCP checksum if protocol is TCP
                    byte protocol = packet[ipOffset + 9]; // IP protocol field

                    if (protocol == 6) // TCP
                    {
                        int ipHeaderLength = (packet[ipOffset] & 0x0F) * 4;
                        int tcpOffset = ipOffset + ipHeaderLength;

                        ushort tcpChecksum = CalculateTcpChecksum(packet, ipOffset);
                        packet[tcpOffset + 16] = (byte)(tcpChecksum >> 8);
                        packet[tcpOffset + 17] = (byte)(tcpChecksum & 0xFF);
                    }

                    Console.WriteLine($"[DEBUG] Retranslate {ip} to {translators[index]}");
                    try
                    {
                        CaptureDevice.SendPacket(packet);

                    }
                    catch { }
                }
            }
        }
        ushort CalculateIpChecksum(byte[] packet, int ipHeaderOffset)
        {
            uint sum = 0;

            for (int i = 0; i < 20; i += 2)
            {
                if (i == 10) continue; // Skip the checksum field

                ushort word = (ushort)((packet[ipHeaderOffset + i] << 8) | packet[ipHeaderOffset + i + 1]);
                sum += word;
            }

            // Add carry bits
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // One's complement
            ushort checksum = (ushort)~sum;
            return checksum;
        }
        /// <summary>
        /// Creates a new ARP session in response to a valid ARP reply packet. It processes the packet and sends an
        /// ARP reply if conditions are met. with the session ID embedded in the sender MAC address.
        /// </summary>
        /// <param name="packet">The byte array contains the ARP packet data used to extract necessary information for processing the ARP
        /// reply.</param>
        private void CreateNewSessionViaARPReply(byte[] packet)
        {
            if (packet[12..14].SequenceEqual<byte>([0x08, 0x06]))
            {
                IPAddress desip = new IPAddress(packet[38..42]);
                var index = BestSubnetMatch(desip);
                if (index >= 0)
                {
                    var Id = NewIdCreate(new MacAddress(packet[6..12]));
                    TranslatorRecords.Add(new TranslatorRecord(DateTime.Now, Id, new MacAddress(packet[6..12]), new IPAddress(packet[28..32])));
                    IPAddress sender_ip = new IPAddress(packet[28..32]);
                    ARP arp = new ARP(targetProtocolAddress: sender_ip, operation: 2, targetHardwareAddress: packet[6..12], SenderProtocolAddress_: desip,
                        /*Injects the SessionId into the Last 2 byte of the senderMac*/
                        SenderMacAddress: new MacAddress([.. SystemMacAddress.MacAddressBytes[0..4], (byte)(Id >> 8), (byte)Id]));
                    arp.Send(true);
                    Console.WriteLine($"[DEBUG] SENT ARP REPLY TO  {desip} / {(MacAddress)packet[6..12]}");

                }
            }
        }

        /// <summary>
        /// Edit the "To" IP Address to the "From" IP Address in our Translator list. and send it to the right device that was tricked into thinking we are the right device.
        /// </summary>
        /// <param name="packet">The byte array representing the network packet that will be modified.</param>
        /// <param name="des">The destination IP address used to determine the new source IP address for the packet.</param>
        public void ModifyDestinationIPV4ToSourceIPV4(byte[] packet, IPAddress des)
        {
            const int ipOffset = 14;

            if (packet[12..14].SequenceEqual<byte>([0x08, 0x00]) && packet.Length >= 34) // 34 includes full IP header
            {
                // Check if the destination IP address("To") matches any of the translators
                var translator = translators.FirstOrDefault(x => x.TranslateTo.Equals(des));
                //If no translator is found, exit the method because we don't need to modify the packet
                if (translator == null) return;

                //we takes the translator "From" IP address and set it to the new destination IP address/ by default the IP Address is currently "To" IPAddress
                var newIp = translator.TranslateFrom.IPAddressBytes;
                if (newIp == null) return;

                MacAddress system_mac = (MacAddress)SystemMacAddress;
                //saves the original id ,taken from the packet destination Mac
                ushort id = (ushort)((packet[4] << 8) | packet[5]);
                //we are reformatting the packet to look like it came from our device and sending it to the Device that owns the Id injected in the last 2 bytes of the des mac address
                var GetOwnerTranslateRecord = FindIdOwner(id);
                //If no owner is found, exit the method because we don't need to modify the packet
                if (GetOwnerTranslateRecord.Mac == null) return;
                // We are editing the src mac so the target have no idea that the packet was redirected
                packet[6] = system_mac[0];
                packet[7] = system_mac[1];
                packet[8] = system_mac[2];
                packet[9] = system_mac[3];
                //ID for the sender
                //so when the target talks to us again it will send it via the mac address we set with it session id injected
                packet[10] = (byte)(GetOwnerTranslateRecord.ID >> 8); // high byte
                packet[11] = (byte)(GetOwnerTranslateRecord.ID);      // low byte


                Console.WriteLine($"[DEBUG] Edited mac to {new MacAddress(packet[6..12])} for {GetOwnerTranslateRecord.IP}");

                // Get ID and resolve original sender


                // we are setting the destination mac address to the owner mac address so we can send the contact directly
                packet[0] = GetOwnerTranslateRecord.Mac[0];
                packet[1] = GetOwnerTranslateRecord.Mac[1];
                packet[2] = GetOwnerTranslateRecord.Mac[2];
                packet[3] = GetOwnerTranslateRecord.Mac[3];
                packet[4] = GetOwnerTranslateRecord.Mac[4];
                packet[5] = GetOwnerTranslateRecord.Mac[5];


                // Rewrite SRC IP (us) and DEST IP (original sender)
                packet[26] = newIp[0];
                packet[27] = newIp[1];
                packet[28] = newIp[2];
                packet[29] = newIp[3];
                packet[30] = GetOwnerTranslateRecord.IP[0];
                packet[31] = GetOwnerTranslateRecord.IP[1];
                packet[32] = GetOwnerTranslateRecord.IP[2];
                packet[33] = GetOwnerTranslateRecord.IP[3];

                // Clear and recalculate IP checksum
                packet[ipOffset + 10] = 0;
                packet[ipOffset + 11] = 0;
                ushort ipChecksum = CalculateIpChecksum(packet, ipOffset);
                packet[ipOffset + 10] = (byte)(ipChecksum >> 8);
                packet[ipOffset + 11] = (byte)(ipChecksum & 0xFF);

                // Recalculate TCP checksum only if protocol == 6 (TCP)
                byte protocol = packet[ipOffset + 9];
                if (protocol == 6)
                {
                    int ipHeaderLength = (packet[ipOffset] & 0x0F) * 4;
                    int tcpOffset = ipOffset + ipHeaderLength;

                    ushort tcpChecksum = CalculateTcpChecksum(packet, ipOffset);
                    packet[tcpOffset + 16] = (byte)(tcpChecksum >> 8);
                    packet[tcpOffset + 17] = (byte)(tcpChecksum & 0xFF);
                }

                Console.WriteLine($"[DEBUG] Retranslate {des} to {string.Join('.', newIp)}");
                CaptureDevice.SendPacket(packet);
            }
        }

        /// <summary>
        /// Finds the best matching subnet index for a given IP address based on CIDR notation.
        /// </summary>
        /// <param name="_ip_to_translate">The IP address to be matched against a list of subnets.</param>
        /// <returns>The index of the best matching subnet or -1 if no match is found.</returns>
        private int BestSubnetMatch(IPAddress _ip_to_translate)
        {

            (int index, int CIDR) cird_info = (-1, 0);
            for (var i = 0; i < translators.Count; i++)
            {
                var item = translators[i];
                var IP = item.TranslateFrom;
                if (BitConverter.ToInt32((byte[])_ip_to_translate) >> (32 - item.CIDR) ==
                    BitConverter.ToInt32((byte[])IP) >> (32 - item.CIDR))
                {
                    var non_mast_c = item.CIDR - 32;
                    if (cird_info.CIDR <= non_mast_c)
                        cird_info = (i, (int)non_mast_c);
                }
            }
            return cird_info.index;

        }
        private ushort CalculateTcpChecksum(byte[] packet, int ipOffset)
        {
            int ipHeaderLength = (packet[ipOffset] & 0x0F) * 4;
            int tcpOffset = ipOffset + ipHeaderLength;

            int totalLength = (packet[ipOffset + 2] << 8) | packet[ipOffset + 3];
            int tcpLength = totalLength - ipHeaderLength;

            // Build pseudo-header
            List<byte> pseudoHeader = new()
                {
                    packet[ipOffset + 12], packet[ipOffset + 13],
                    packet[ipOffset + 14], packet[ipOffset + 15], // Src IP
                    packet[ipOffset + 16], packet[ipOffset + 17],
                    packet[ipOffset + 18], packet[ipOffset + 19], // Dst IP
                    0x00,
                    packet[ipOffset + 9], // Protocol (TCP = 6)
                    (byte)(tcpLength >> 8), (byte)(tcpLength & 0xFF)
                };

            // Copy TCP segment into temp array, and zero checksum bytes
            byte[] tcpSegment = new byte[tcpLength];
            Array.Copy(packet, tcpOffset, tcpSegment, 0, tcpLength);
            tcpSegment[16] = 0;
            tcpSegment[17] = 0;

            // Concatenate pseudo-header + tcp segment
            byte[] checksumData = pseudoHeader.Concat(tcpSegment).ToArray();

            return CalculateChecksum(checksumData);
        }

        private ushort CalculateChecksum(byte[] data)
        {
            uint sum = 0;
            int i = 0;
            while (i < data.Length - 1)
            {
                sum += (ushort)((data[i] << 8) | data[i + 1]);
                i += 2;
            }

            if (i < data.Length)
                sum += (ushort)(data[i] << 8); // pad last byte if odd

            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);

            return (ushort)~sum;
        }


        private List<Translator> translators = new List<Translator>();
        /// <summary>
        /// Adds a translator to a collection after checking for overlapping subnets. If a conflict is found, an
        /// exception is thrown.
        /// </summary>
        /// <param name="translator">The parameter represents a translator object containing IP address and CIDR information for validation.</param>
        /// <exception cref="Exception">Thrown when an IP address with the same subnet is already defined in the collection.</exception>
        public void AddTranslator(Translator translator)
        {
            var IP = BitConverter.ToInt32(translator.TranslateFrom.IPAddressBytes);

            if (translators.Any(x => IP >> (translator.CIDR - 32) == x.TranslateFrom >> (translator.CIDR - 32)))
            {
                throw new Exception($"IP With the same Subnet is already defined: {IP}/{translator.CIDR}");
            }
            translators.Add(translator);
        }
        public bool RemoveTranslator(Translator translator)
        => translators.Remove(translator);

    }

}