package org.craftercms.commons.licensing;

import java.io.Serializable;

public interface SiteLimit extends Serializable {

    int getNumberOfSites();

    void setNumberOfSites(int numberOfSites);
}
