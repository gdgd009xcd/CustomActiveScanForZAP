package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public interface LcsBuilder<T> {
	public void append(T t);
	public void add(int index, T t);
	public List<T> getLCS();
	public int size();
	public void clear();
	public void appenddiffA(T ta);
	public void appenddiffB(T tb);
	public void setdiffB(List<T> lb);
	public void setReverseLCS();
	public void setABreverse(boolean b);
	public List<T> getDiffA();
	public List<T> getDiffB();
}
