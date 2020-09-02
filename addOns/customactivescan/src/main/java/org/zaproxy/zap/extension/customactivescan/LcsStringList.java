package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class LcsStringList implements LcsBuilder<String>{
	List<String> strings;
	List<String> diffa;
	List<String> diffb;
	String lcschars;
	Object[] diffs = null;
	boolean reverse;
	boolean ABreverse = false;
	
	
	LcsStringList(){
		clear();
	}
	
	@Override
	public void append(String s) {
		strings.add(s);
	}
	
	@Override
	public void add(int index, String s) {
		strings.add(index, s);
	}

	/**
	 * get List of Longest Common Subsequene from two Strings
	 *
	 * @return
	 */
	@Override
	public List<String> getLCS(){// return reverse order list
		if(reverse) {
			List<String> revlist = new ArrayList<String>(strings);
			Collections.reverse(revlist);
			return revlist;
		}
		return strings;
	}

	/**
	 * get String of Longest Common Subsequence from two strings.
	 *
	 * @return
	 */
	public String getLCSString(){
		return String.join("", getLCS());
	}
	
	@Override
	public int size() {
		return strings.size();
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void clear() {
		strings = new ArrayList<String>();
		diffa = new ArrayList<String>();
		diffb = new ArrayList<String>();
		lcschars = null;
		reverse = false;
		diffs = new Object[2];
		if(ABreverse) {
			diffs[0] = diffb;
			diffs[1] = diffa;
		}else {
			diffs[0] = diffa;
			diffs[1] = diffb;
		}
		
	}
	
	@SuppressWarnings("unchecked")
    public ArrayList<String> cast(Object obj) {
        return (ArrayList<String>) obj;
    }
	
	@Override
	public void appenddiffA(String ta) {
		// TODO Auto-generated method stub
		cast(diffs[0]).add(ta);
	}
	
	@Override
	public void appenddiffB(String tb) {
		// TODO Auto-generated method stub
		cast(diffs[1]).add(tb);
	}

	@Override
	public void setdiffB(List<String> lb) {
		// TODO Auto-generated method stub
		cast(diffs[1]).addAll(lb);
	}
	
	@Override
	public List<String> getDiffA(){
		return diffa;
	}
	
	@Override
	public List<String> getDiffB(){
		return diffb;
	}

	public void addDiffA(List<String> ad) {
		diffa.addAll(ad);
	}
	
	public void addDiffB(List<String> ad) {
		diffb.addAll(ad);
	}
	
	@Override
	public void setReverseLCS() {
		// TODO Auto-generated method stub
		reverse = true;
	}
	
	@Override
	public void setABreverse(boolean b) {
		ABreverse = b;
	}

	/* obsolete */
	public void obsolete_setLcsChars(String c) {
		lcschars = c;
	}

	/* obsolete */
	public String obsolete_getLcsChars() {
		return lcschars;
	}

}
