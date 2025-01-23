package com.shumu.xiehe;

import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.NifSelector;

import com.shumu.xiehe.TcpReassembler.TcpSession;

public class TcpReassembler {

  public static final Map<String, TcpSession> sessions = new HashMap<String, TcpSession>();

  public static void main(String[] args)
      throws PcapNativeException, NotOpenException {
    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    handle.setFilter(
        "tcp port 9998",
//        args[1],
        BpfCompileMode.OPTIMIZE);

    for (int i = 3; i < args.length; i++) {
      sessions.put("/" + args[i], new TcpSession());
    }

    while (true) {
      try {
        Packet packet = handle.getNextPacketEx();
        TcpPacket tcp = packet.get(TcpPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);

        if (tcp == null) {
          continue;
        }

        String sKey = ip.getHeader().getSrcAddr().toString() + ":"
            + tcp.getHeader().getSrcPort().valueAsInt();

//        boolean isToServer = true;
//        TcpPort port = tcp.getHeader().getSrcPort();
//        if (port.value() == 9998) {
//          port = tcp.getHeader().getDstPort();
//          isToServer = false;
//        }

        boolean syn = tcp.getHeader().getSyn();
        boolean fin = tcp.getHeader().getFin();
        boolean rst = tcp.getHeader().getRst();

        if (syn || fin || rst) {
          TcpSession session = sessions.get(sKey).init(tcp);

//          if (isToServer) {
//            TcpSession session = sessions.get(sKey);
////            sessions.put(sKey, session);
//          } else {
//            session = sessions.get(sKey);
//          }
//          long seq = tcp.getHeader().getSequenceNumberAsLong();
//          session.setSeqNumOffset(isToServer, seq + 1L);

//        } else if (fin) {
//          TcpSession session = sessions.get(sKey);
//          session.getPackets(isToServer).add(tcp);
//
//          byte[] reassembledPayload = doReassemble(
//              session.getPackets(isToServer),
//              session.getSeqNumOffset(isToServer),
//              tcp.getHeader().getSequenceNumberAsLong(),
//              tcp.getPayload().length());
//
//          int len = reassembledPayload.length;
//          for (int i = 0; i < len;) {
//            try {
//              TcpPacket tls = TcpPacket.newPacket(
//                  reassembledPayload,
//                  i,
//                  len - i);
//              System.out.println(tls);
//              i += tls.length();
//            } catch (IllegalRawDataException e) {
//              e.printStackTrace();
//            }
//          }
        } else {
          if (tcp.getPayload() != null && tcp.getPayload().length() != 0) {
            TcpSession session = sessions.get(sKey).addSession(tcp);
//            session.getPackets(isToServer).add(tcp);
          }
        }
      } catch (TimeoutException e) {
        continue;
      } catch (EOFException e) {
        break;
      }
    }

    handle.close();
  }

  private static byte[] doReassemble(
      List<TcpPacket> packets, long seqNumOffset, long lastSeqNum,
      int lastDataLen) {
    // This cast is not safe.
    // The sequence number is unsigned int and so
    // (int) (lastSeqNum - seqNumOffset) may be negative.
    byte[] buffer = new byte[(int) (lastSeqNum - seqNumOffset) + lastDataLen];

    for (TcpPacket p : packets) {
      byte[] payload = p.getPayload().getRawData();
      long seq = p.getHeader().getSequenceNumberAsLong();
      System.arraycopy(
          payload,
          0,
          buffer,
          (int) (seq - seqNumOffset),
          payload.length);
    }

    return buffer;
  }

  public static final class TcpSession {
    long nxt = 0;
    long isn = 0;

    private final List<TcpPacket> packetsToServer = new ArrayList<TcpPacket>();
    private final List<TcpPacket> packetsToClient = new ArrayList<TcpPacket>();
    private final List<TcpPacket> packets = new ArrayList<TcpPacket>();
    private long serverSeqNumOffset;
    private long clientSeqNumOffset;

    public TcpSession init(TcpPacket tcp) {
      packets.clear();
      this.isn = tcp.getHeader().getAcknowledgmentNumberAsLong();
      this.nxt = isn;
      return this;
    }

    public TcpSession addSession(TcpPacket tcp) {
      if (isn == 0) {
        this.isn = tcp.getHeader().getAcknowledgmentNumberAsLong();
        this.nxt = isn;
      }

      int i = 0;
      for (; i < packets.size(); i++) {
        TcpPacket p = packets.get(i);
        if (p.getHeader().getSequenceNumberAsLong() < tcp.getHeader()
            .getSequenceNumberAsLong()) {
          continue;
        } else if (p.getHeader().getSequenceNumberAsLong() == tcp.getHeader()
            .getSequenceNumberAsLong()) {
          packets.remove(i);
          break;
        }
      }
      packets.add(i, tcp);
      return this;
    }

    public TcpPacket pop() {
      TcpPacket tcp = packets.getFirst();
      if (nxt == tcp.getHeader().getAcknowledgmentNumberAsLong()) {
        tcp = packets.removeFirst();
        nxt += tcp.getPayload().length();
      }
      return tcp;
    }

    public List<TcpPacket> getPackets(boolean toServer) {
      if (toServer) {
        return packetsToServer;
      } else {
        return packetsToClient;
      }
    }

    public long getSeqNumOffset(boolean toServer) {
      if (toServer) {
        return clientSeqNumOffset;
      } else {
        return serverSeqNumOffset;
      }
    }

    public void setSeqNumOffset(boolean toServer, long seqNumOffset) {
      if (toServer) {
        this.clientSeqNumOffset = seqNumOffset;
      } else {
        this.serverSeqNumOffset = seqNumOffset;
      }
    }
  }
}
