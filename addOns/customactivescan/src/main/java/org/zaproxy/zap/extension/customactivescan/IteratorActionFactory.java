package org.zaproxy.zap.extension.customactivescan;

import java.util.List;
import java.util.ListIterator;

public class IteratorActionFactory<T> {

    IteratorActionFactory() {/* nothing to do. */}

    public IteratorAction<T> getGenericIteratorAction(List<T> geneticList, boolean reverse) {
        return getGenericIteratorActionInternal(geneticList, 0, reverse);
    }

    public IteratorAction<T> getGenericIteratorAction(List<T> geneticList, int startIndex, boolean reverse) {
        return getGenericIteratorActionInternal(geneticList, startIndex, reverse);
    }

    /**
     * get IteratorAction which start from startIndex
     * @param geneticList
     * @param startIndex
     * @param reverse
     * @return
     */
    private IteratorAction<T> getGenericIteratorActionInternal(List<T> geneticList, int startIndex, boolean reverse) {
        if (reverse) {
            return new IteratorAction<T>() {
                private ListIterator<T> it = geneticList.listIterator(geneticList.size()-startIndex);

                @Override
                public void rewind() {
                    it = geneticList.listIterator(geneticList.size()-startIndex);
                }

                @Override
                public T getNext() {
                    if (it.hasPrevious()) return it.previous();
                    return null;
                }
            };
        }
        return new IteratorAction<T>() {
            private ListIterator<T> it = geneticList.listIterator(startIndex);

            @Override
            public void rewind() {
                it = geneticList.listIterator(startIndex);
            }

            @Override
            public T getNext() {
                if (it.hasNext()) return it.next();
                return null;
            }
        };
    }
}
