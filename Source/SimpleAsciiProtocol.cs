using NICDevice.Interfaces;
using System.Text;

public class SimpleAsciiProtocol(string asciiMessage) : ILayer
{
    public byte[] LayerBytes { get; set; }= Encoding.ASCII.GetBytes(asciiMessage);
    public byte[] Payload()
    {
        return LayerBytes;
    }
}
