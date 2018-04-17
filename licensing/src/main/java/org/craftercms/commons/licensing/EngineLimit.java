package org.craftercms.commons.licensing;

public class EngineLimit implements SiteLimit {
    private static final long serialVersionUID = 2015099443095265475L;

    private int numberOfSites;

    @Override
    public int getNumberOfSites() {
        return numberOfSites;
    }

    @Override
    public void setNumberOfSites(int numberOfSites) {
        this.numberOfSites = numberOfSites;
    }
}
