using NICDevice.IP;

namespace EthernetTranslator_CSharp
{
    public record Translator(IPAddress TranslateFrom, int CIDR, IPAddress TranslateTo)
    {
        public override string ToString()
        {
            return $"{TranslateFrom}/{CIDR} {TranslateTo}";
        }
    }
}