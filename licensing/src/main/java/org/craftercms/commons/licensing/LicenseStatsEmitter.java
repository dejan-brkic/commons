package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.model.LicenseStats;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class LicenseStatsEmitter {

    private DatagramSocket socket;
    private InetAddress address;
    private int port;

    private byte[] buffer;

    public LicenseStatsEmitter() throws SocketException, UnknownHostException {
        socket = new DatagramSocket();
        address = InetAddress.getLocalHost();
        port = 4545;
    }

    public void sendStats(LicenseStats stats) throws IOException {
        Yaml yaml = new Yaml();
        String statsMessage = yaml.dump(stats);
        buffer = statsMessage.getBytes();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, port);
        socket.send(packet);
    }
}
