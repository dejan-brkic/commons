package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.model.LicenseStats;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

public class LicenseStatsServer {

    private DatagramSocket socket;
    private boolean running;
    private byte[] buffer = new byte[1024];

    public LicenseStatsServer() throws SocketException {
        socket = new DatagramSocket(4545);
    }

    public void run() throws IOException {
        running = true;
        while (running) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            InetAddress address = packet.getAddress();
            int port = packet.getPort();
            packet = new DatagramPacket(buffer, buffer.length, address, port);
            String received = new String(packet.getData(), 0, packet.getLength());
            received = received.trim();

            Yaml yaml = new Yaml();
            LicenseStats licenseStats = yaml.loadAs(received, LicenseStats.class);
            System.out.println(yaml.dumpAsMap(licenseStats));

            if (received.equals("end")) {
                running = false;
                continue;
            }
            socket.send(packet);
        }
        socket.close();
    }
}
