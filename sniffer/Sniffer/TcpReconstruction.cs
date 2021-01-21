using MathNet.Numerics.Statistics; // Install-Package MathNet.Numerics
using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;

// https://www.codeproject.com/Articles/20501/TCP-Session-Reconstruction-Tool

// Translated from the file follow.c from WireShark source code
// the code can be found at: http://www.wireshark.org/download.html
// follow.c => Copyright 1998 Mike Hall<mlh@io.com>

// Here we are going to try and reconstruct the data portion of a TCP
// session. We will try and handle duplicates, TCP fragments, and out
// of order packets in a smart way.

namespace Sniffer
{
    // A class that represent a node in a linked list that holds partial Tcp 
    // session fragments
    internal class TcpFragment
    {
        public ulong seq = 0;
        public ulong len = 0;
        public ulong dataLength = 0;
        public byte[] data = null;
        public TcpFragment next = null;
    };

    class TcpReconstruction
    {
        // Holds two linked list of the session data, one for each direction    
        TcpFragment[] frags = new TcpFragment[2];
        // Holds the last sequence number for each direction
        ulong[] sequenceNumber = new ulong[2];
        long[] sourceAddress = new long[2];
        uint[] sourcePort = new uint[2];
        bool emptyTcpStream = true;
        uint[] tcpPort = new uint[2];
        uint[] bytesWritten = new uint[2];
        System.IO.FileStream fileStream = null;
        bool incompleteTcpStream = false;
        bool closed = false;

        public DateTime flowStartTime; // 7, G
        public DateTime fwdStartTime;
        public DateTime bwdStartTime;
        public DateTime flowLastSeen;
        public DateTime fwdLastSeen;
        public DateTime bwdLastSeen;
        public TimeSpan duration; // 8, H

        public List<long> packetSizeList = new List<long>();
        public List<long> packetSizeFwdList = new List<long>();
        public List<long> packetSizeBwdList = new List<long>();
        public List<double> flowIATList = new List<double>();
        public List<double> fwdIATList = new List<double>();
        public List<double> bwdIATList = new List<double>();
        
        // [Kahram 2018, Appendix A]
        public long totalPackets = 0;
        public long totalFwdPackets = 0; // 9, I
        public long totalBwdPackets = 0; // 10, J
        public long totalLengthOfFwdPackets = 0; // 11, K
        public long totalLengthOfBwdPackets = 0; // 12, L
        public long fwdPacketLengthMax = 0; // 13, M
        public long fwdPacketLengthMin = 0; // 14, N
        public double fwdPacketLengthMean = 0; // 15, O
        public double fwdPacketLengthStd = 0; // 16, P
        public long bwdPacketLengthMax = 0; // 17, Q
        public long bwdPacketLengthMin = 0; // 18, R
        public double bwdPacketLengthMean = 0; // 19, S
        public double bwdPacketLengthStd = 0; // 20, T

        // IAT = inter-arrival time, research application error [Kahram2018]
        public double flowIATMean = 0; // 23, W
        public double flowIATStd = 0; // 24, X
        public double flowIATMax = 0; // 25, Y
        public double flowIATMin = 0; // 26, Z
        public double fwdIATTotal = 0; // 27, AA
        public double fwdIATMean = 0; // 28, AB
        public double fwdIATStd = 0; // 29, AC
        public double fwdIATMax = 0; // 30, AD
        public double fwdIATMin = 0; // 31, AE
        public double bwdIATTotal = 0; // 32, AF
        public double bwdIATMean = 0; // 33, AG
        public double bwdIATStd = 0; // 34, AH
        public double bwdIATMax = 0; // 35, AI
        public double bwdIATMin = 0; // 36, AJ

        // 37, AK, Fwd PSH Flags
        // 38, AL, Bwd PSH Flags
        // 39, AM, Fwd URG Flags
        // 40, AN, Bwd URG Flags

        public long fwdHeaderLength = 0; // 41, AO
        public long bwdHeaderLength = 0; // 42, AP
        // GetFwdPacketsPerSecond() // 43, AQ
        // GetBwdPacketsPerSecond() // 44, AR

        public long minPacketLength = 0; // 44, AS
        public long maxPacketLength = 0; // 45, AT
        public double packetLengthMean = 0; // 46, AU
        public double packetLengthStd = 0; // 47, AV
        public double packetLengthVariance = 0; // 48, AW

        // 49, AX, FIN Flag Count
        // 50, AY, SYN Flag Count
        // 51, AZ, RST Flag Count
        // 52, BA, PSH Flag Count
        // 53, BB, ACK Flag Count
        // 54, BC, URG Flag Count
        // 55, BD, CWE Flag Count
        // 56, BE, ECE Flag Count
        // 57, BF, Down/Up Ratio

        public double averagePacketSize = 0; // 58, BG
        public double averageFwdSegmentSize = 0; // 59, BH
        public double averageBwdSegmentSize = 0; // 60, BH

        public int subflowCount = -1;
        public double subflowStartTimeTS;
        public double subflowLastSeenTS;

        public void CalculateStatistics()
        {
            // http://www.netflowmeter.ca/netflowmeter.html
            // https://github.com/ISCX/CICFlowMeter/blob/1d4e34eee43fd2e5fc37bf37dbae0558ca7c17fe/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java
            // 
            // dumpFlowBasedFeatures()

            duration = flowLastSeen - flowStartTime;

            packetSizeList = packetSizeFwdList.Concat(packetSizeBwdList).ToList();

            if (packetSizeFwdList.Count > 0)
            {
                fwdPacketLengthMax = packetSizeFwdList.Max();
                fwdPacketLengthMin = packetSizeFwdList.Min();
                fwdPacketLengthMean = packetSizeFwdList.Average();
                if (packetSizeFwdList.Count > 1) fwdPacketLengthStd = Statistics.StandardDeviation(packetSizeFwdList.Select(x => (double)x));

                if (fwdIATList.Count > 0)
                {
                    fwdIATTotal = fwdIATList.Sum();
                    fwdIATMean = fwdIATList.Average();
                    if (fwdIATList.Count > 1) fwdIATStd = Statistics.StandardDeviation(fwdIATList.Select(x => (double)x));
                    fwdIATMax = fwdIATList.Max();
                    fwdIATMin = fwdIATList.Min();
                }
                
                averageFwdSegmentSize = packetSizeFwdList.Average();
            }

            if (packetSizeBwdList.Count > 0)
            {
                bwdPacketLengthMax = packetSizeBwdList.Max();
                bwdPacketLengthMin = packetSizeBwdList.Min();
                bwdPacketLengthMean = packetSizeBwdList.Average();
                if (packetSizeBwdList.Count > 1) bwdPacketLengthStd = Statistics.StandardDeviation(packetSizeBwdList.Select(x => (double)x));

                if (bwdIATList.Count > 0)
                {
                    bwdIATTotal = bwdIATList.Sum();
                    bwdIATMean = bwdIATList.Average();
                    if (bwdIATList.Count > 1) bwdIATStd = Statistics.StandardDeviation(bwdIATList.Select(x => (double)x));
                    bwdIATMax = bwdIATList.Max();
                    bwdIATMin = bwdIATList.Min();
                }

                averageBwdSegmentSize = packetSizeBwdList.Average();
            }

            if (flowIATList.Count > 0)
            {
                flowIATMean = flowIATList.Average();
                if (flowIATList.Count > 1) flowIATStd = Statistics.StandardDeviation(flowIATList.Select(x => (double)x));
                flowIATMax = flowIATList.Max();
                flowIATMin = flowIATList.Min();
            }

            averagePacketSize = packetSizeList.Sum() / (double)(totalFwdPackets + totalBwdPackets); 
            minPacketLength = packetSizeList.Min();
            maxPacketLength = packetSizeList.Max();
            packetLengthMean = packetSizeList.Average();
            if (packetSizeList.Count > 1) packetLengthStd = Statistics.StandardDeviation(packetSizeList.Select(x => (double)x));
            if (packetSizeList.Count > 1) packetLengthVariance = Statistics.Variance(packetSizeList.Select(x => (double)x));
        }

        public TcpReconstruction(string filename)
        {
            ResetTcpReassembly();
            fileStream = new System.IO.FileStream(filename, System.IO.FileMode.Create);
        }

        // Сlean the linked list
        void ResetTcpReassembly()
        {
            TcpFragment current, next;
            int i;

            emptyTcpStream = true;
            incompleteTcpStream = false;

            for (i = 0; i < 2; i++)
            {
                sequenceNumber[i] = 0;
                sourceAddress[i] = 0;
                sourcePort[i] = 0;
                tcpPort[i] = 0;
                bytesWritten[i] = 0;
                current = frags[i];

                while (current != null)
                {
                    next = current.next;
                    current.data = null;
                    current = null;
                    current = next;
                }
                frags[i] = null;
            }
        }

        public void Close()
        {
            if (!closed)
            {
                fileStream.Close();
                ResetTcpReassembly();
                closed = true;
            }
        }

        ~TcpReconstruction()
        {
            Close();
        }

        // Writes the payload data to the file
        private void WritePacketData(int index, byte[] data)
        {
            // Ignore empty packets
            if (data.Length == 0) return;

            fileStream.Write(data, 0, data.Length);
            bytesWritten[index] += (uint)data.Length;
            emptyTcpStream = false;
        }

        public string GetTimestampString()
        {
            TimeSpan threeHours = new TimeSpan(3, 0, 0);
            DateTime convertedDateTime = flowStartTime.Subtract(threeHours);
            return convertedDateTime.ToString("dd.MM.yyyy HH:mm:ss");
        }

        public double GetFwdPacketsPerSecond()
        {
            // Duration is in milliseconds, therefore packets per seconds = packets / (duration / 1000)
            double durationInMilliseconds = (flowLastSeen - flowStartTime).TotalMilliseconds;
            if (durationInMilliseconds > 0)
            {
                return ((double)totalFwdPackets) / (durationInMilliseconds / 1000L);
            }
            else
                return 0;
        }

        public double GetBwdPacketsPerSecond()
        {
            // Duration is in milliseconds, therefore packets per seconds = packets / (duration / 1000)
            double durationInMilliseconds = (flowLastSeen - flowStartTime).TotalMilliseconds;
            if (durationInMilliseconds > 0)
            {
                return ((double)totalBwdPackets) / (durationInMilliseconds / 1000L);
            }
            else
                return 0;
        }

        public double GetFlowBytesPerSecond()
        {
            // Duration is in milliseconds, therefore bytes per seconds = bytes / (duration / 1000)
            double duration = (flowLastSeen - flowStartTime).TotalMilliseconds;
            if (duration > 0)
            {
                double res = totalLengthOfFwdPackets + totalLengthOfBwdPackets;
                res = res / (duration / 1000);
                return res;
            }
            else
                return 0;
        }

        public double GetPacketsPerSecond()
        {
            // Duration is in milliseconds, therefore bytes per seconds = bytes / (duration / 1000)
            double duration = (flowLastSeen - flowStartTime).TotalMilliseconds;
            if (duration > 0)
            {
                double res = totalFwdPackets + totalBwdPackets;
                res = res / (duration / 1000);
                return res;
            }
            else
                return 0;
        }

        public void ReassemblePacket(Packet packet, DateTime pcapTimeVal)
        {
            var ip = (PacketDotNet.IpPacket)packet.Extract(typeof(PacketDotNet.IpPacket));
            if (ip != null)
            {
                var tcpPacket = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));

                // If the paylod length is zero bail out
                // long length = tcpPacket.BytesHighPerformance.Length - tcpPacket.Header.Length;
                // if (length == 0) return;

                ReassembleTcp(
                    (ulong)tcpPacket.SequenceNumber,
                    (ulong)tcpPacket.BytesHighPerformance.Length,
                    tcpPacket.PayloadData,
                    (ulong)tcpPacket.PayloadData.Length,
                    tcpPacket.Syn,
                    (long)(uint)ip.SourceAddress.Address,
                    (long)(uint)ip.DestinationAddress.Address,
                    (uint)tcpPacket.SourcePort,
                    (uint)tcpPacket.DestinationPort
                );

                // Update statistics
                if (totalFwdPackets == 0 && totalBwdPackets == 0)
                {
                    // flowStartTime = DateTime.Now;
                    flowStartTime = pcapTimeVal;
                    flowLastSeen = flowStartTime;
                }

                double flowDuration = (double)(pcapTimeVal - flowStartTime).TotalMilliseconds * 1000;
                if (flowDuration > 120000000) return;

                totalPackets++;

                double duration = (double)(pcapTimeVal - flowLastSeen).TotalMilliseconds * 1000;
                // In order not to write duration = 0 for the first packet in the session
                if (totalFwdPackets + totalBwdPackets > 0)  flowIATList.Add(duration); 

                // flowLastSeen = DateTime.Now;
                flowLastSeen = pcapTimeVal;

                // Process subflows
                double currentTS = (pcapTimeVal.Ticks / TimeSpan.TicksPerMillisecond) * 1000;
                if (subflowCount == -1)
                {
                    subflowStartTimeTS = currentTS;
                    subflowLastSeenTS = currentTS;
                }
                double delta = currentTS - (subflowLastSeenTS);
                double expr = (currentTS - (subflowLastSeenTS) / (double)1000000);
                if ((currentTS - (subflowLastSeenTS) / (double)1000000) > 1.0)
                {
                    subflowCount++;
                    subflowStartTimeTS = currentTS;
                }
                subflowLastSeenTS = currentTS;

                // In the original research there is a peculiarity (error) in determining the length of a TCP packet 
                // if the IP length is <46 bytes.
                // Ethernet adds padding up to 46 bytes, and this padding counts as the length of the TCP payload
                long length = (long)tcpPacket.PayloadData.Length;
                if (ip.TotalLength < 46) length = 46 - ip.TotalLength;

                // Forward
                if (ip.SourceAddress.Address == sourceAddress[0] &&
                    (uint)tcpPacket.SourcePort == sourcePort[0])
                {
                    if (totalFwdPackets == 0)
                    {
                        fwdStartTime = pcapTimeVal;
                        fwdLastSeen = fwdStartTime;
                    } else
                    {
                        double fwdDuration = (double)(pcapTimeVal - fwdLastSeen).TotalMilliseconds * 1000;
                        fwdIATList.Add(fwdDuration);
                        fwdLastSeen = pcapTimeVal;
                    }

                    totalFwdPackets++;
                    totalLengthOfFwdPackets += length;
                    packetSizeFwdList.Add(length);
                    fwdHeaderLength += tcpPacket.Header.Length;
                }
                // Backward
                if (ip.SourceAddress.Address == sourceAddress[1] &&
                    (uint)tcpPacket.SourcePort == sourcePort[1])
                {
                    if (totalBwdPackets == 0)
                    {
                        bwdStartTime = pcapTimeVal;
                        bwdLastSeen = bwdStartTime;
                    } else
                    {
                        double bwdDuration = (double)(pcapTimeVal - bwdLastSeen).TotalMilliseconds * 1000;
                        bwdIATList.Add(bwdDuration);
                        bwdLastSeen = pcapTimeVal;
                    }

                    totalBwdPackets++;
                    totalLengthOfBwdPackets += length;
                    packetSizeBwdList.Add(length);
                    bwdHeaderLength += tcpPacket.Header.Length;
                }
            }
        }

        private void ReassembleTcp(ulong packetSequenceNumber, ulong packetLength, byte[] packetData,
                                   ulong packetDataLength, bool synFlag, 
                                   long packetSourceAddress, long packetDestinationAddress, 
                                   uint packetSourcePort, uint packetDestinationPort)
        {
            int sourceIndex, j;
            bool first = false;
            ulong newseq;
            TcpFragment tmp_frag;

            sourceIndex = -1;

            // Now check if the packet is for this connection.
            // Check to see if we have seen this source IP and port before.
            // (Yes, we have to check both source IP and port; the connection
            // might be between two different ports on the same machine.)
            for (j = 0; j < 2; j++)
            {
                if (sourceAddress[j] == packetSourceAddress && sourcePort[j] == packetSourcePort)
                {
                    sourceIndex = j;
                }
            }

            // We didn't find it if sourceIndex == -1
            if (sourceIndex < 0)
            {
                // Assign it to a sourceIndex and get going
                for (j = 0; j < 2; j++)
                {
                    if (sourcePort[j] == 0)
                    {
                        sourceAddress[j] = packetSourceAddress;
                        sourcePort[j] = packetSourcePort;
                        sourceIndex = j;
                        first = true;
                        break;
                    }
                }
            }
            if (sourceIndex < 0) throw new Exception("ERROR in ReassembleTcp: Too many addresses!");

            if (packetDataLength < packetLength) incompleteTcpStream = true;
            
            // Now that we have filed away the srcs, lets get the sequence number stuff figured out
            if (first)
            {
                // This is the first time we have seen this src's sequence number
                sequenceNumber[sourceIndex] = packetSequenceNumber + packetLength;
                if (synFlag) sequenceNumber[sourceIndex]++;

                WritePacketData(sourceIndex, packetData);
                return;
            }

            // If we are here, we have already seen this src, 
            // let's try and figure out if this packet is in the right place
            if (packetSequenceNumber < sequenceNumber[sourceIndex])
            {
                // This sequence number seems dated, but check the end to make sure it has no more
                // info than we have already seen
                newseq = packetSequenceNumber + packetLength;
                if (newseq > sequenceNumber[sourceIndex])
                {
                    ulong new_len;

                    // This one has more than we have seen. Let's get the payload that we have not seen.
                    new_len = sequenceNumber[sourceIndex] - packetSequenceNumber;

                    if (packetDataLength <= new_len)
                    {
                        packetData = null;
                        packetDataLength = 0;
                        incompleteTcpStream = true;
                    }
                    else
                    {
                        packetDataLength -= new_len;
                        byte[] tmpData = new byte[packetDataLength];
                        for (ulong i = 0; i < packetDataLength; i++)
                            tmpData[i] = packetData[i + new_len];

                        packetData = tmpData;
                    }
                    packetSequenceNumber = sequenceNumber[sourceIndex];
                    packetLength = newseq - sequenceNumber[sourceIndex];

                    // This will now appear to be right on time :)
                }
            }
            if (packetSequenceNumber == sequenceNumber[sourceIndex])
            {
                // Right on time
                sequenceNumber[sourceIndex] += packetLength;
                if (synFlag) sequenceNumber[sourceIndex]++;
                if (packetData != null)
                {
                    WritePacketData(sourceIndex, packetData);
                }
                // Done with the packet, see if it caused a fragment to fit
                while (CheckFragments(sourceIndex))
                    ;
            }
            else
            {
                // Out of order packet
                if (packetDataLength > 0 && packetSequenceNumber > sequenceNumber[sourceIndex])
                {
                    tmp_frag = new TcpFragment();
                    tmp_frag.data = packetData;
                    tmp_frag.seq = packetSequenceNumber;
                    tmp_frag.len = packetLength;
                    tmp_frag.dataLength = packetDataLength;

                    if (frags[sourceIndex] != null)
                    {
                        tmp_frag.next = frags[sourceIndex];
                    }
                    else
                    {
                        tmp_frag.next = null;
                    }
                    frags[sourceIndex] = tmp_frag;
                }
            }
        }

        // Here we search through all the frag we have collected to see if one fits
        bool CheckFragments(int index)
        {
            TcpFragment prev = null;
            TcpFragment current;
            current = frags[index];
            while (current != null)
            {
                if (current.seq == sequenceNumber[index])
                {
                    // This fragment fits the stream
                    if (current.data != null)
                    {
                        WritePacketData(index, current.data);
                    }
                    sequenceNumber[index] += current.len;
                    if (prev != null)
                    {
                        prev.next = current.next;
                    }
                    else
                    {
                        frags[index] = current.next;
                    }
                    current.data = null;
                    current = null;
                    return true;
                }
                prev = current;
                current = current.next;
            }
            return false;
        }
    }
}
