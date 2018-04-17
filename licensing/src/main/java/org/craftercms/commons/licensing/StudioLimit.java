package org.craftercms.commons.licensing;

public class StudioLimit implements UserLimit, SiteLimit, ItemLimit {

    private static final long serialVersionUID = 486629718301939283L;

    private int numberOfItems;
    private int numberOfSites;
    private int numberOfUsers;

    @Override
    public int getNumberOfItems() {
        return numberOfItems;
    }

    @Override
    public void setNumberOfItems(int numberOfItems) {
        this.numberOfItems = numberOfItems;
    }

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
