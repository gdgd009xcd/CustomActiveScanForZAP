package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public interface ArrayListWrapper<T> {
    public int size();
    public T get(int index);
    public boolean isOriginalReverseOrder();
    public List<T> getOriginalList();
    public int getRowSize();
    public String getDelimiter();
}
