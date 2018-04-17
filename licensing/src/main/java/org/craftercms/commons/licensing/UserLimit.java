package org.craftercms.commons.licensing;

import java.io.Serializable;

public interface UserLimit extends Serializable {

    int getNumberOfUsers();

    void setNumberOfUsers(int numberOfUsers);
}
