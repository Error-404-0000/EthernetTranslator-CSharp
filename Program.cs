namespace EthernetTranslator_CSharp
{
    internal  class Program
    {

        static async Task Main(string[] args)
        {

            TranslateManager translatemanager = new TranslateManager();
            Translator TOGateWay = new Translator("10.0.0.99", 32, "10.0.0.101");

            translatemanager.AddTranslator(TOGateWay);
            ////less likly to work except if we tell our device to accpt it by chaning to subnet 10.0.0.0 with anything less than <20
            //translatemanager.AddTranslator(new Translator("10.0.1.1", 28, "1.1.1.1"));

            //translatemanager.AddTranslator(new Translator("10.0.0.130", 32, "8.8.8.8"));
            Console.Read();

        }
    }
}