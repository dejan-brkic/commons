package org.craftercms.commons.licensing;

import java.io.Serializable;

public interface ItemLimit extends Serializable {

    int getNumberOfItems();

    void setNumberOfItems(int numberOfItems);
}
