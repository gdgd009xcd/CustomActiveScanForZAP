package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public interface LcsBuilder<T> {
	public void append(T t);
	public int size();
	public void clear();
	public void appenddiffA(T ta);
	public void appenddiffB(T tb);
	public void setReverse();
	public boolean isReverseLCS();
	public boolean isReverseDiffA();
	public boolean isReverseDiffB();
	public void setABreverse(boolean b);
	public T getLcsElement(int index);
	public T getDiffAElement(int index);
	public void setOriginalDiffA(ArrayListWrapper<T> wrapperDiffA);
	public T getDiffBElement(int index);
	public void setOriginalDiffB(ArrayListWrapper<T> wrapperDiffB);
	public int getDiffASize();
	public int getDiffBSize();
}
