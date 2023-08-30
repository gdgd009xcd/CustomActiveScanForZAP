package org.zaproxy.zap.extension.customactivescan;

public interface IteratorAction<T> {
    public void rewind();
    public T getNext();
}
