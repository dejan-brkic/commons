package org.craftercms.commons.licensing;

public class ProfileLimit implements SiteLimit, UserLimit {
    private static final long serialVersionUID = 175463273166215898L;

    private int numberOfSites;
    private int numberOfUsers;

    @Override
    public int getNumberOfSites() {
        return numberOfSites;
    }

    @Override
    public void setNumberOfSites(int numberOfSites) {
        this.numberOfSites = numberOfSites;
    }

    @Override
    public int getNumberOfUsers() {
        return numberOfUsers;
    }

    @Override
    public void setNumberOfUsers(int numberOfUsers) {
        this.numberOfUsers = numberOfUsers;
    }
}
