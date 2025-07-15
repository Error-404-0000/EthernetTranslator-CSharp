using NICDevice.IP;
using NICDevice.MAC;

namespace EthernetTranslator_CSharp
{
   
        public class TranslatorRecord(DateTime timespan, ushort ID, MacAddress ownerMac,IPAddress OwnerIPAddress)
        {
            public DateTime DateTime { get; set; } = timespan;
            public ushort ID { get; } = ID;
            public MacAddress OwnerMac { get; } = ownerMac;
            public IPAddress OwnerIPAddress { get; } = OwnerIPAddress;

            public override string ToString()
            {
                return $"{DateTime.Second}:Seconds {ID} {OwnerMac}";
            }
        }
    
}