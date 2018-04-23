package org.craftercms.commons.licensing;

import java.io.Serializable;

public interface DescriptorLimit extends Serializable {

    int getNumberOfDescriptors();

    void setNumberOfDescriptors(int numberOfDescriptor);
}
