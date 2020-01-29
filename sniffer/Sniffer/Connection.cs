using System;
using PacketDotNet;

namespace Sniffer
{
    class Connection
    {
        private string m_srcIp;
        public string SourceIp
        {
            get { return m_srcIp; }
        }

        private ushort m_srcPort;
        public ushort SourcePort
        {
            get { return m_srcPort; }
        }

        private string m_dstIp;
        public string DestinationIp
        {
            get { return m_dstIp; }
        }

        private ushort m_dstPort;
        public ushort DestinationPort
        {
            get { return m_dstPort; }
        }

        public Connection(string sourceIP, UInt16 sourcePort, string destinationIP, UInt16 destinationPort)
        {
            m_srcIp = sourceIP;
            m_dstIp = destinationIP;
            m_srcPort = sourcePort;
            m_dstPort = destinationPort;
        }

        public Connection(Packet packet)
        {
            m_srcIp = "unknown";
            m_dstIp = "unknown";
            m_srcPort = 0;
            m_dstPort = 0;

            var ip = (PacketDotNet.IpPacket)packet.Extract(typeof(PacketDotNet.IpPacket));
            if (ip != null)
            {
                m_srcIp = ip.SourceAddress.ToString();
                m_dstIp = ip.DestinationAddress.ToString();

                var tcp = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
                if (tcp != null)
                {
                    m_srcPort = tcp.SourcePort;
                    m_dstPort = tcp.DestinationPort;
                }
            }
        }

        /// <summary>
        /// Overrided in order to catch both sides of the connection 
        /// with the same connection object
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (!(obj is Connection))
                return false;
            Connection con = (Connection)obj;

            bool result = ((con.SourceIp.Equals(m_srcIp)) && (con.SourcePort == m_srcPort) && (con.DestinationIp.Equals(m_dstIp)) && (con.DestinationPort == m_dstPort)) 
                || ((con.SourceIp.Equals(m_dstIp)) && (con.SourcePort == m_dstPort) && (con.DestinationIp.Equals(m_srcIp)) && (con.DestinationPort == m_srcPort));

            return result;
        }

        public override int GetHashCode()
        {
            return ((m_srcIp.GetHashCode() ^ m_srcPort.GetHashCode()) as object).GetHashCode() ^
                ((m_dstIp.GetHashCode() ^ m_dstPort.GetHashCode()) as object).GetHashCode();
        }

        public string getFileName(string path)
        {
            return string.Format("{0}{1}.{2}-{3}.{4}.data", path, m_srcIp, m_srcPort, m_dstIp, m_dstPort);
        }

        public override string ToString()
        {
            return string.Format("{0}:{1} -> {2}:{3}", m_srcIp, m_srcPort, m_dstIp, m_dstPort);
        }
    }
}
