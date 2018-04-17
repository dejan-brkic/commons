package org.craftercms.commons.licensing;

public class SocialLimit implements SiteLimit, ItemLimit {
    private static final long serialVersionUID = -5359880223562643165L;

    private int numberOfItems;
    private int numberOfSites;

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
}
