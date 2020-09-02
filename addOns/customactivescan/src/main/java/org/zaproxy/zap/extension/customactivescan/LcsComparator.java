package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public interface LcsComparator<T> {
	int calcLCS(List<T> a, List<T> b, LcsBuilder<T> result);
	int calcPercent(List<T> a, List<T> b, LcsBuilder<T> result);
}
