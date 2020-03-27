using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Configuration;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Globalization;

namespace Sniffer
{
    class Program
    {
        // Read configuration from App.config
        private static string pcapName = GetAppSetting("PcapName", "5mb.pcap");
        private static string sessionDir = GetAppSetting("SessionDir", @"c:\sessions\");
        private static string datasetName = GetAppSetting("DatasetName", "packets_train.csv");
        private static string datasetMinifiedName = GetAppSetting("DatasetMinifiedName", "packets_train_minified.csv");

        // Used to stop the capture loop
        private static Boolean stopCapturing = false;

        private static DateTime startTime;
        private static Dictionary<Connection, TcpReconstruction> connections = new Dictionary<Connection, TcpReconstruction>();

        static void Main(string[] args)
        {
            startTime = DateTime.Now;

            // Print version
            String ver = SharpPcap.Version.VersionString;
            Console.WriteLine("ML-IDS Sniffer using SharpPcap {0}", ver);

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            Int32 i = 0;

            // Print out the devices
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }
            Console.WriteLine("{0}) {1}", i, "Read packets from offline pcap file");

            // https://github.com/chmorgan/sharppcap/blob/master/Examples/Example12.PacketManipulation/Example12.PacketManipulation.cs
            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            var choice = Int32.Parse(Console.ReadLine());

            ICaptureDevice device = null;
            bool offlinePcap = false;
            if (choice == i)
            {
                Console.Write(@"-- Please enter an input capture file name [" + pcapName + "]: ");
                string capFile = Console.ReadLine();
                if (capFile.Length < 2) capFile = pcapName;
                device = new CaptureFileReaderDevice(capFile);
                offlinePcap = true;
            }
            else
            {
                device = devices[choice];
            }

            // Register a cancel handler that lets us break out of our capture loop
            Console.CancelKeyPress += HandleCancelKeyPress;

            // Open the device for capturing
            Int32 readTimeoutMilliseconds = 1000;
            if (offlinePcap)
                device.Open();
            else
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // https://wiki.wireshark.org/CaptureFilters
            // tcpdump filter to capture only SSH packets (port 22) and RDP packets (port 3389)
            // string filter = "port 22 || port 3389";
            // device.Filter = filter;

            string filter = "tcp";
            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine("-- The following tcpdump filter will be applied: \"{0}\"", filter);

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0}, hit 'ctrl-c' to stop...", device.Name);

            StringBuilder csv = new StringBuilder();

            int counter = 0;
            while (stopCapturing == false)
            {
                counter++;
                // if (counter > 6000) continue;
                var rawCapture = device.GetNextPacket();
                
                // Null packets can be returned in the case where
                // the GetNextRawPacket() timed out, we should just attempt
                // to retrieve another packet by looping the while() again
                if (rawCapture == null)
                {
                    // Go back to the start of the while()
                    continue;
                }

                // Use PacketDotNet to parse this packet and print out its high level information
                Packet packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);

                // Create a key for the dictionary
                Connection c = new Connection(packet);

                // Create a new entry if the key does not exists
                if (!connections.ContainsKey(c))
                {
                    string fileName = c.getFileName(sessionDir);
                    TcpReconstruction tcpReconstruction = new TcpReconstruction(fileName);
                    connections.Add(c, tcpReconstruction);
                    Console.WriteLine(c.ToString());
                }

                // Use the TcpReconstruction class to reconstruct the session
                connections[c].ReassemblePacket(packet, rawCapture.Timeval.Date);

                if (packet is PacketDotNet.EthernetPacket)
                {
                    String messageToConsole = "";
                    // String messageToRabbit = "";
                    String protocol = "";

                    var eth = ((PacketDotNet.EthernetPacket)packet);
                    // messageToConsole = "Eth => ";

                    // Manipulate ethernet parameters
                    // eth.SourceHwAddress = PhysicalAddress.Parse("00-11-22-33-44-55");
                    // eth.DestinationHwAddress = PhysicalAddress.Parse("00-99-88-77-66-55");

                    var ip = (PacketDotNet.IpPacket)packet.Extract(typeof(PacketDotNet.IpPacket));
                    if (ip != null)
                    {
                        // messageToConsole += "IP => "; // + ip.ToString());

                        // Manipulate IP parameters
                        // ip.SourceAddress = System.Net.IPAddress.Parse("1.2.3.4");
                        // ip.DestinationAddress = System.Net.IPAddress.Parse("44.33.22.11");
                        // ip.TimeToLive = 11;

                        var tcp = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
                        if (tcp != null)
                        {
                            // if (tcp.DestinationPort == 22 || tcp.SourcePort == 22) protocol = "SSH";
                            // if (tcp.DestinationPort == 3389 || tcp.SourcePort == 3389) protocol = "RDP";

                            // HARD ZASLON DEMO
                            // if (protocol == "SSH") protocol = "SSH New Keys";
                            // if (protocol == "RDP") protocol = "RDP COTP";

                            messageToConsole += String.Format("TCP packet: {0}:{1} -> {2}:{3} {4} {5}", ip.SourceAddress, tcp.SourcePort,
                                ip.DestinationAddress, tcp.DestinationPort, protocol, ip.TotalLength); // + tcp.ToString());
                            // messageToRabbit = String.Format("{0}|||{1}|||{2}|||{3}|||{4}|||{5}", protocol, ip.SourceAddress, tcp.SourcePort,
                            //    ip.DestinationAddress, tcp.DestinationPort, ip.TotalLength); // + tcp.ToString());

                            // Manipulate TCP parameters
                            // tcp.SourcePort = 9999;
                            // tcp.DestinationPort = 8888;
                            // tcp.Syn = !tcp.Syn;
                            // tcp.Fin = !tcp.Fin;
                            // tcp.Ack = !tcp.Ack;
                            // tcp.WindowSize = 500;
                            // tcp.AcknowledgmentNumber = 800;
                            // tcp.SequenceNumber = 800;

                            var newLine = String.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15}",
                                DateTime.Now.ToString("yyyy-MM-dd"), DateTime.Now.ToString("hh-mm-ss-fff"),
                                eth.SourceHwAddress, eth.DestinationHwAddress,
                                ip.SourceAddress, tcp.SourcePort, ip.DestinationAddress, tcp.DestinationPort,
                                ip.TotalLength,
                                tcp.Syn, tcp.Fin, tcp.Ack,
                                tcp.WindowSize, tcp.AcknowledgmentNumber, tcp.SequenceNumber,
                                ip.TimeToLive
                            );
                            csv.AppendLine(newLine);
                        }

                        var udp = (PacketDotNet.UdpPacket)packet.Extract(typeof(PacketDotNet.UdpPacket));
                        if (udp != null)
                        {
                            messageToConsole += String.Format("UDP packet: {0}:{1} -> {2}:{3} {4}", ip.SourceAddress, udp.SourcePort,
                                ip.DestinationAddress, udp.DestinationPort, ip.TotalLength); // + udp.ToString());

                            // Manipulate UDP parameters
                            // udp.SourcePort = 9999;
                            // udp.DestinationPort = 8888;
                        }

                    } // if (ip != null)
                } // if (packet is PacketDotNet.EthernetPacket)
            } // while (stopCapturing == false)

            Console.WriteLine("-- Capture stopped");

            // Print out the device statistics
            try
            {
                if (!offlinePcap) Console.WriteLine(device.Statistics.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            
            // Close the pcap device
            device.Close();
        }

        static void HandleCancelKeyPress(Object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("-- Stopping capture");

            DateTime finishTime = DateTime.Now;
            TimeSpan totalTime = (finishTime - startTime);

            Console.WriteLine(string.Format("\nTotal reconstruct time: {0} seconds", totalTime.TotalSeconds));

            stopCapturing = true;

            // Write data to CSV and close TcpReconstruction objects
            StringBuilder csv = new StringBuilder();
            StringBuilder csvMinified = new StringBuilder();

            foreach (TcpReconstruction tr in connections.Values)
            {
                // tr.CalculateStatistics();
                var newLine = String.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}",
                    tr.GetTimestampString(),
                    tr.totalPackets,
                    tr.totalFwdPackets, // 9
                    tr.totalBwdPackets, // 10
                    tr.totalLengthOfFwdPackets, // 11
                    tr.totalLengthOfBwdPackets, // 12
                    tr.fwdPacketLengthMean.ToString("F2", CultureInfo.InvariantCulture), // 15
                    tr.fwdPacketLengthStd.ToString("F2", CultureInfo.InvariantCulture), // 16
                    tr.bwdPacketLengthMean.ToString("F2", CultureInfo.InvariantCulture), // 19
                    tr.bwdPacketLengthStd.ToString("F2", CultureInfo.InvariantCulture), // 20
                    tr.bwdPacketLengthMax, // 17
                    tr.GetFlowBytesPerSecond().ToString("F2", CultureInfo.InvariantCulture), // 21
                    (tr.GetFlowBytesPerSecond() / 1000000).ToString("F2", CultureInfo.InvariantCulture), // 21
                    tr.flowIATMax.ToString("F2", CultureInfo.InvariantCulture) // 25
                );
                csv.AppendLine(newLine);
                
                newLine = String.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13}",
                    tr.totalLengthOfFwdPackets, // 11
                    tr.fwdPacketLengthMean.ToString("F2", CultureInfo.InvariantCulture), // 15
                    tr.bwdPacketLengthStd.ToString("F2", CultureInfo.InvariantCulture), // 20
                    tr.GetFlowBytesPerSecond().ToString("F2", CultureInfo.InvariantCulture), // 21
                    tr.flowIATMax.ToString("F2", CultureInfo.InvariantCulture), // 25
                    tr.GetTimestampString(),
                    tr.totalPackets,
                    tr.totalFwdPackets, // 9
                    tr.totalBwdPackets, // 10
                    tr.totalLengthOfBwdPackets, // 12
                    tr.fwdPacketLengthStd.ToString("F2", CultureInfo.InvariantCulture), // 16
                    tr.bwdPacketLengthMean.ToString("F2", CultureInfo.InvariantCulture), // 19
                    tr.bwdPacketLengthMax, // 17
                    (tr.GetFlowBytesPerSecond() / 1000000).ToString("F2", CultureInfo.InvariantCulture) // 21
                );
                csvMinified.AppendLine(newLine);
                tr.Close();
            }
            connections.Clear();
            
            using (StreamWriter sw = new StreamWriter(datasetName))
            {
                Console.WriteLine(datasetName);
                sw.WriteLine(
                    "Timestamp," +
                    "Total Packets," +
                    "Total Fwd Packets," +
                    "Total Backword Packets," +
                    "Total Length of Fwd Packets," +
                    "Total Length of Bwd Packets," +
                    "Fwd Packet Length Mean," +
                    "Fwd Packet Length Std," +
                    "Bwd Packet Length Mean," +
                    "Bwd Packet Length Std," +
                    "Bwd Packet Length Max," +
                    "Flow Bytes/s," +
                    "Flow MB/s," +
                    "Flow IAT Max (TotalMilliseconds)"
                );
                sw.Write(csv);
            }

            using (StreamWriter sw = new StreamWriter(datasetMinifiedName))
            {
                sw.WriteLine(
                    "Total Length of Fwd Packets," +
                    "Fwd Packet Length Mean," +
                    "Bwd Packet Length Std," +
                    "Flow Bytes/s," +
                    "Flow IAT Max," +
                    "Timestamp," +
                    "Total Packets," +
                    "Total Fwd Packets," +
                    "Total Backword Packets," +
                    "Total Length of Bwd Packets," +
                    "Fwd Packet Length Std," +
                    "Bwd Packet Length Mean," +
                    "Bwd Packet Length Max," +
                    "Flow MB/s"
                    );
                sw.Write(csvMinified);
            }

            // Tell the handler that we are taking care of shutting down, don't
            // shut us down after we return because we need to do just a little
            // bit more processing to close the open capture device etc
            e.Cancel = true;
        }

        public static string GetAppSetting(string key, string def = "not exists")
        {
            if (ConfigurationManager.AppSettings[key] != null)
                return ConfigurationManager.AppSettings[key].ToString();
            return def;
        }
    }
}
