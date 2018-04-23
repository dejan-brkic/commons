package org.craftercms.commons.licensing;

public class StudioLimit implements UserLimit, SiteLimit, DescriptorLimit, AssetLimit {

    private static final long serialVersionUID = 486629718301939283L;

    private int numberOfDescriptors;
    private int numberOfAssets;
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

    @Override
    public int getNumberOfDescriptors() {
        return numberOfDescriptors;
    }

    @Override
    public void setNumberOfDescriptors(int numberOfDescriptors) {
        this.numberOfDescriptors = numberOfDescriptors;
    }

    @Override
    public int getNumberOfAssets() {
        return numberOfAssets;
    }

    @Override
    public void setNumberOfAssets(int numberOfAssets) {
        this.numberOfAssets = numberOfAssets;
    }
}
