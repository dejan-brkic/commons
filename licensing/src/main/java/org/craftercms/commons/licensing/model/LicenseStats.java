package org.craftercms.commons.licensing.model;

import java.io.Serializable;
import java.time.ZonedDateTime;

public class LicenseStats implements Serializable {
    private static final long serialVersionUID = 944381411058215L;

    protected String licenseId;
    protected String client;
    protected String component;
    protected String macAddress;
    protected String ipAddress;
    protected String host;
    protected String osName;
    protected String osVersion;
    protected String startupTime;
    protected long runDuration;
    protected String lastUpdate;

    public String getLicenseId() {
        return licenseId;
    }

    public void setLicenseId(String licenseId) {
        this.licenseId = licenseId;
    }

    public String getClient() {
        return client;
    }

    public void setClient(String client) {
        this.client = client;
    }

    public String getComponent() {
        return component;
    }

    public void setComponent(String component) {
        this.component = component;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getOsName() {
        return osName;
    }

    public void setOsName(String osName) {
        this.osName = osName;
    }

    public String getOsVersion() {
        return osVersion;
    }

    public void setOsVersion(String osVersion) {
        this.osVersion = osVersion;
    }

    public String getStartupTime() {
        return startupTime;
    }

    public void setStartupTime(String startupTime) {
        this.startupTime = startupTime;
    }

    public long getRunDuration() {
        return runDuration;
    }

    public void setRunDuration(long runDuration) {
        this.runDuration = runDuration;
    }

    public String getLastUpdate() {
        return lastUpdate;
    }

    public void setLastUpdate(String lastUpdate) {
        this.lastUpdate = lastUpdate;
    }
}
