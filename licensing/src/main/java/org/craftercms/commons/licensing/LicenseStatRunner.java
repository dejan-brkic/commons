package org.craftercms.commons.licensing;

import org.craftercms.commons.licensing.model.LicenseStats;

import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public class LicenseStatRunner {

    public static void main(String[] args) throws IOException {

        System.getProperties().list(System.out);


        LicenseStatsServer server = new LicenseStatsServer();
        Thread serverThread = new Thread() {
            public void run() {
                try {
                    server.run();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };
        serverThread.start();

        for (int i = 0; i < 10; i++) {
            LicenseStats licenseStats = new LicenseStats();
            licenseStats.setClient("Client");
            licenseStats.setComponent("Component");
            licenseStats.setHost("Host");
            licenseStats.setIpAddress("IP Address");
            licenseStats.setLastUpdate("Last Update");
            licenseStats.setLicenseId("License ID");
            licenseStats.setMacAddress("MAC Address");
            licenseStats.setOsName("Os Name");
            licenseStats.setOsVersion("OS Version");
            licenseStats.setRunDuration(i);
            licenseStats.setStartupTime(ZonedDateTime.now(ZoneOffset.UTC).toString());

            LicenseStatsEmitter emitter = new LicenseStatsEmitter();
            emitter.sendStats(licenseStats);
        }


    }
}
