package org.craftercms.commons.licensing;

import java.io.Serializable;

public interface AssetLimit extends Serializable {

    int getNumberOfAssets();

    void setNumberOfAssets(int numberOfAssets);
}
