using PacketDotNet; // Manually add PacketDotNet.dll to references
using SharpPcap; // Manually add SharpPcap.dll to references
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
        private static string pcapName = GetAppSetting("PcapName", "test1.pcap");
        private static string sessionDir = GetAppSetting("SessionDir", @"c:\sniffer\sessions\");
        private static string datasetName = GetAppSetting("DatasetName", "packets_train.csv");
        private static string datasetMinifiedName = GetAppSetting("DatasetMinifiedName", "packets_train_minified.csv");

        // Used to stop the capture loop
        private static Boolean stopCapturing = false;

        private static DateTime startTime;
        private static Dictionary<Connection, TcpReconstruction> connections = new Dictionary<Connection, TcpReconstruction>();

        // Results
        public static StringBuilder csv = new StringBuilder();
        public static StringBuilder csvMinified = new StringBuilder();

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
                TcpReconstruction tcpReconstruction;

                // Create a new entry if the key does not exists
                if (!connections.ContainsKey(c))
                {
                    string fileName = c.getFileName(sessionDir);
                    tcpReconstruction = new TcpReconstruction(fileName);
                    connections.Add(c, tcpReconstruction);
                    Console.WriteLine(c.ToString());
                }

                // Use the TcpReconstruction class to reconstruct the session
                connections[c].ReassemblePacket(packet, rawCapture.Timeval.Date);

                // Do like CICFlowMeter
                var tcp = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
                if (tcp != null && tcp.Fin && connections[c].totalPackets > 1)
                {
                    var ethP = ((PacketDotNet.EthernetPacket)packet);
                    
                    OutputFinishedSession(c, connections[c]);
                    connections.Remove(c);
                }

                if (packet is PacketDotNet.EthernetPacket)
                {
                    String messageToConsole = "";
                    String protocol = "";

                    var eth = ((PacketDotNet.EthernetPacket)packet);

                    // Manipulate ethernet parameters
                    // eth.SourceHwAddress = PhysicalAddress.Parse("00-11-22-33-44-55");
                    // eth.DestinationHwAddress = PhysicalAddress.Parse("00-99-88-77-66-55");

                    var ip = (PacketDotNet.IpPacket)packet.Extract(typeof(PacketDotNet.IpPacket));
                    if (ip != null)
                    {
                        // Manipulate IP parameters
                        // ip.SourceAddress = System.Net.IPAddress.Parse("1.2.3.4");
                        // ip.DestinationAddress = System.Net.IPAddress.Parse("44.33.22.11");
                        // ip.TimeToLive = 11;

                        tcp = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
                        if (tcp != null)
                        {
                            // if (tcp.DestinationPort == 22 || tcp.SourcePort == 22) protocol = "SSH";
                            // if (tcp.DestinationPort == 3389 || tcp.SourcePort == 3389) protocol = "RDP";

                            messageToConsole += String.Format("TCP packet: {0}:{1} -> {2}:{3} {4} {5}", ip.SourceAddress, tcp.SourcePort,
                                ip.DestinationAddress, tcp.DestinationPort, protocol, ip.TotalLength); // + tcp.ToString());

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
                            // csv.AppendLine(newLine);
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

            // Complete all sessions
            foreach (KeyValuePair<Connection, TcpReconstruction> kvp in connections)
            {
                OutputFinishedSession(kvp.Key, kvp.Value);
            }
            connections.Clear();

            using (StreamWriter sw = new StreamWriter(datasetName))
            {
                Console.WriteLine(datasetName);
                sw.WriteLine(
                    "Flow Key," + // 1, A
                    "Source IP," + // 2, B
                    "Source Port," + // 3, C
                    "Destination IP," + // 4, D
                    "Destination Port," + // 5, E
                    "Protocol," + // protocol = TCP 6, F
                    "Timestamp," + // 7, G
                    "Flow Duration," + // 8, H
                    "Total Packets," +
                    "Total Fwd Packets," + // 9, I
                    "Total Backword Packets," + // 10, J
                    "Total Length of Fwd Packets," + // 11, K
                    "Total Length of Bwd Packets," + // 12, L
                    "Fwd Packet Length Max," + // 13, M
                    "Fwd Packet Length Min," + // 14, N
                    "Fwd Packet Length Mean," + // 15, O
                    "Fwd Packet Length Std," + // 16, P
                    "Bwd Packet Length Max," + // 17, Q
                    "Bwd Packet Length Min," + // 18, R
                    "Bwd Packet Length Mean," + // 19, S
                    "Bwd Packet Length Std," + // 20, T
                    "Flow Bytes/s," + // 21, U
                    "Flow MB/s," +
                    "Flow Packets/s," + // 22, V
                    "Flow IAT Mean," + // 23, W
                    "Flow IAT Std," + // 24, X
                    "Flow IAT Max," + // 25, Y
                    "Flow IAT Min," + // 26, Z
                    "Fwd IAT Total," + // 27, AA
                    "Fwd IAT Mean," + // 28, AB
                    "Fwd IAT Std," + // 29, AC
                    "Fwd IAT Max," + // 30, AD
                    "Fwd IAT Min," + // 31, AE
                    "Bwd IAT Total," + // 32, AF
                    "Bwd IAT Mean," + // 33, AG
                    "Bwd IAT Std," + // 34, AH
                    "Bwd IAT Max," + // 35, AI
                    "Bwd IAT Min," +  // 36, AJ
                    // 37, AK, Fwd PSH Flags
                    // 38, AL, Bwd PSH Flags
                    // 39, AM, Fwd URG Flags
                    // 40, AN, Bwd URG Flags
                    "Fwd Header Length," + // 41, AO
                    "Bwd Header Length," + // 42, AP
                    "Fwd Packets/s," + // 43, AQ
                    "Bwd Packets/s," + // 44, AR
                    "Min Packet Length," + // 44, AS
                    "Max Packet Length," + // 45, AT
                    "Packet Length Mean," + // 46, AU
                    "Packet Length Std," + // 47, AV
                    "Packet Length Variance," + // 48, AW
                    // 49, AX, FIN Flag Count
                    // 50, AY, SYN Flag Count
                    // 51, AZ, RST Flag Count
                    // 52, BA, PSH Flag Count
                    // 53, BB, ACK Flag Count
                    // 54, BC, URG Flag Count
                    // 55, BD, CWE Flag Count
                    // 56, BE, ECE Flag Count
                    // 57, BF, Down/Up Ratio
                    "Average Packet Size," + // 58, BG
                    "Average Fwd Segment Size," + // 59, BH
                    "Average Bwd Segment Size," + // 60, BH
                    "Packet Length List"
                );
                sw.Write(csv);
            }

            using (StreamWriter sw = new StreamWriter(datasetMinifiedName))
            {
                sw.WriteLine(
                    "Flow Key," +
                    "Flow Bytes/s," +
                    "Average Packet Size," +
                    "Max Packet Length," +
                    "Packet Length Mean," +
                    "Fwd Packet Length Mean," +
                    "Fwd IAT Min," +
                    "Total Length of Fwd Packets," +
                    "Avg Fwd Segment Size," +
                    "Flow IAT Mean," +
                    "Fwd Packet Length Max"
                );
                sw.Write(csvMinified);
            }
        }

        static void OutputFinishedSession(Connection c, TcpReconstruction tr)
        {
            // Write data to CSV and close TcpReconstruction objects

            tr.CalculateStatistics();
            var newLine = String.Format(
                "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20}," +
                "{21},{22},{23},{24},{25},{26},{27},{28},{29},{30},{31},{32},{33},{34},{35},{36},{37},{38},{39}," +
                "{40},{41},{42},{43},{44},{45},{46},{47},{48},{49},{50}",
                c.ToString(), // 1, A
                c.SourceIp, // 2, B
                c.SourcePort, // 3, C
                c.DestinationIp, // 4, D
                c.DestinationPort, // 5, E
                "6", // protocol = TCP 6, F
                tr.GetTimestampString(), // 7, G
                tr.duration.TotalMilliseconds * 1000, // 8, H
                tr.totalPackets,
                tr.totalFwdPackets, // 9, I
                tr.totalBwdPackets, // 10, J
                tr.totalLengthOfFwdPackets, // 11, K
                tr.totalLengthOfBwdPackets, // 12, L
                tr.fwdPacketLengthMax, // 13, M
                tr.fwdPacketLengthMin, // 14, N
                tr.fwdPacketLengthMean.ToString("F5", CultureInfo.InvariantCulture), // 15, O
                tr.fwdPacketLengthStd.ToString("F5", CultureInfo.InvariantCulture), // 16, P
                tr.bwdPacketLengthMax, // 17, Q
                tr.bwdPacketLengthMin, // 18, R
                tr.bwdPacketLengthMean.ToString("F5", CultureInfo.InvariantCulture), // 19, S
                tr.bwdPacketLengthStd.ToString("F5", CultureInfo.InvariantCulture), // 20, T
                tr.GetFlowBytesPerSecond().ToString("F5", CultureInfo.InvariantCulture), // 21, U
                (tr.GetFlowBytesPerSecond() / 1000000).ToString("F5", CultureInfo.InvariantCulture),
                tr.GetPacketsPerSecond().ToString("F5", CultureInfo.InvariantCulture), // 22, V

                tr.flowIATMean.ToString("F5", CultureInfo.InvariantCulture), // 23, W
                tr.flowIATStd.ToString("F5", CultureInfo.InvariantCulture), // 24, X
                tr.flowIATMax.ToString("F5", CultureInfo.InvariantCulture), // 25, Y
                tr.flowIATMin.ToString("F5", CultureInfo.InvariantCulture), // 26, Z
                tr.fwdIATTotal.ToString("F5", CultureInfo.InvariantCulture), // 27, AA
                tr.fwdIATMean.ToString("F5", CultureInfo.InvariantCulture), // 28, AB
                tr.fwdIATStd.ToString("F5", CultureInfo.InvariantCulture), // 29, AC
                tr.fwdIATMax.ToString("F5", CultureInfo.InvariantCulture), // 30, AD
                tr.fwdIATMin.ToString("F5", CultureInfo.InvariantCulture), // 31, AE
                tr.bwdIATTotal.ToString("F5", CultureInfo.InvariantCulture), // 32, AF
                tr.bwdIATMean.ToString("F5", CultureInfo.InvariantCulture), // 33, AG
                tr.bwdIATStd.ToString("F5", CultureInfo.InvariantCulture), // 34, AH
                tr.bwdIATMax.ToString("F5", CultureInfo.InvariantCulture), // 35, AI
                tr.bwdIATMin.ToString("F5", CultureInfo.InvariantCulture), // 36, AJ

                // 37, AK, Fwd PSH Flags
                // 38, AL, Bwd PSH Flags
                // 39, AM, Fwd URG Flags
                // 40, AN, Bwd URG Flags

                tr.fwdHeaderLength, // 41, AO
                tr.bwdHeaderLength, // 42, AP
                tr.GetFwdPacketsPerSecond().ToString("F5", CultureInfo.InvariantCulture), // 43, AQ
                tr.GetBwdPacketsPerSecond().ToString("F5", CultureInfo.InvariantCulture), // 44, AR
                tr.minPacketLength, // 44, AS
                tr.maxPacketLength, // 45, AT
                tr.packetLengthMean.ToString("F5", CultureInfo.InvariantCulture), // 46, AU
                tr.packetLengthStd.ToString("F5", CultureInfo.InvariantCulture), // 47, AV
                tr.packetLengthVariance.ToString("F5", CultureInfo.InvariantCulture), // 48, AW

                // 49, AX, FIN Flag Count
                // 50, AY, SYN Flag Count
                // 51, AZ, RST Flag Count
                // 52, BA, PSH Flag Count
                // 53, BB, ACK Flag Count
                // 54, BC, URG Flag Count
                // 55, BD, CWE Flag Count
                // 56, BE, ECE Flag Count
                // 57, BF, Down/Up Ratio

                tr.averagePacketSize.ToString("F5", CultureInfo.InvariantCulture), // 58, BG
                tr.averageFwdSegmentSize.ToString("F5", CultureInfo.InvariantCulture), // 59, BH
                tr.averageBwdSegmentSize.ToString("F5", CultureInfo.InvariantCulture), // 60, BH

                tr.subflowCount

            );
            csv.AppendLine(newLine);

            var newLineMinified = String.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}",
                c.ToString(), // FlowKey
                tr.GetFlowBytesPerSecond().ToString("F5", CultureInfo.InvariantCulture),
                tr.averagePacketSize.ToString("F5", CultureInfo.InvariantCulture),
                tr.maxPacketLength,
                tr.packetLengthMean.ToString("F5", CultureInfo.InvariantCulture),
                tr.fwdPacketLengthMean.ToString("F5", CultureInfo.InvariantCulture),
                tr.flowIATMin.ToString("F5", CultureInfo.InvariantCulture), // 25
                tr.totalLengthOfFwdPackets,
                tr.averageFwdSegmentSize.ToString("F5", CultureInfo.InvariantCulture),
                tr.flowIATMean.ToString("F5", CultureInfo.InvariantCulture),
                tr.fwdPacketLengthMax
            );
            csvMinified.AppendLine(newLineMinified);
            
            tr.Close();
        }

        static void HandleCancelKeyPress(Object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("-- Stopping capture");

            DateTime finishTime = DateTime.Now;
            TimeSpan totalTime = (finishTime - startTime);

            Console.WriteLine(string.Format("\nTotal reconstruct time: {0} seconds", totalTime.TotalSeconds));

            stopCapturing = true;

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
