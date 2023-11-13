package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public interface LcsBuilder<T> {
	public void append(T t);
	public int size();
	public void clear();
	public void appendDiffA(T ta);
	public void appendDiffB(T tb);
	public void appendLcsIdxOnDiffA(int idx);
	public List<Integer> getLcsIdxOnDiffA();
	public List<Integer> getLcsIdxOnDiffB();
	public void appendLcsIdxOnDiffB(int idx);
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
	public void setWrapperSourceA(ArrayListWrapper<T> wrapperSourceA);
	public void setWrapperSourceB(ArrayListWrapper<T> wrapperSourceB);


}
