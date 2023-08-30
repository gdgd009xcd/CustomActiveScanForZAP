package org.zaproxy.zap.extension.customactivescan;

public interface LcsComparator<T> {
	int calcLCS(ArrayListWrapper<T> a, ArrayListWrapper<T> b, LcsBuilder<T> result);
	int calcPercent(ArrayListWrapper<T> a, ArrayListWrapper<T> b, LcsBuilder<T> result);
}
