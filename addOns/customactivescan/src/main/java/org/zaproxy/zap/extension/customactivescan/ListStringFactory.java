package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.List;

public class ListStringFactory {

	static int DEFAULT_ROWUNIT = 10000;
	private int n;
	private int rowunit;
	private int origrowsiz ;
	List<String> records;
	StringSplitter splitter = null;
	
	ListStringFactory(String dlm, int custom_unit) {
		n= 1;
		if(custom_unit > 0) {
			rowunit = custom_unit;
		} else {
			rowunit = DEFAULT_ROWUNIT;
		}
		splitter = new StringSplitter(dlm);
	}
	

	
	public int calcRowSize(String lines) {
		
		records = splitter.split(lines);
		origrowsiz = records.size();
		n = origrowsiz / rowunit + 1;
		return n;
	}
	
	public int getOrigRowSize() {
		return origrowsiz;
	}
	
	public void setRowSize(int _n) {
		n = _n;
	}
	
	public int getRowSize() {
		return n;
	}
	
	List<String> getLFSplittedStringList(String b){
		List<String> splinesB = new ArrayList<String>();
		int x = 0;
		
		List<String> blist = records;
		if(b!=null) {
			blist = splitter.split(b);
		}
		
		int reclen = blist.size();
		
		for(int stp = 0; stp < reclen ; stp+=n) {
			int etp = stp + n;
			if(etp>reclen) {
				etp = reclen;
			}
			String joinedstring = String.join("", blist.subList(stp, etp));
			splinesB.add(joinedstring);
		}
		
		return splinesB;
	}
	
	
}
