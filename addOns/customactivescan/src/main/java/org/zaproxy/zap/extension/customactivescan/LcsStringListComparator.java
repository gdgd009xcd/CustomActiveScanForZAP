package org.zaproxy.zap.extension.customactivescan;

import org.apache.log4j.Logger;

import java.util.List;

public class LcsStringListComparator extends LcsOnp<String>{
	static Logger log = Logger.getLogger(LcsStringListComparator.class);

	int MINROWLENGTH = 500; // if contents line count < MINROWLENGTH, then split contents by whitespace.
	int EXTRACTLCS_UNIT = 500000; // extractLCS row unit.
	int MINWORDCNT = 50; // if word count of splitted response fewer than this value, then split again with WHITESPCPLUS delimiter.
	public static int MINCHARSIZE = 0; // if response string size is less than MINCHARSIZE, then  calculate LCS  in character units

	// default split delimiter.
	String WHITESPC = "[ \r\t\n]+";

	// more precise split delimiter.
	String WHITESPCPLUS = "[ ,{}:\"\r\t\n]+";
	
	LcsStringListComparator(){
		super(log);
	}

	/**
	 * extract LCS from a and b which are same request's response.
	 * @param a
	 * @param b
	 * @param LCSresult
	 * @return
	 */
	int extractLCS(String a , String b, LcsStringList LCSresult) {

		if(a==null) {
			a = "";
		}
		
		if(b==null) {
			b = "";
		}

		// currently, below CharacterList base difference calculating code is NO used because detection may be fail.
		// response string size is less than MINCHARSIZE, then  calculate LCS  in character units
		if (a.length() < MINCHARSIZE && b.length() < MINCHARSIZE) {
			CharacterList ca = new CharacterList(a);
			CharacterList cb = new CharacterList(b);
			LcsCharacterList clcs = new LcsCharacterList();
			int cpercent = calcPercentChar(ca, cb,  clcs) ;
			LCSresult.initLcsCharacterList(clcs);
			return cpercent;
		}

		ListStringFactory w_lsfctA = new ListStringFactory(WHITESPC, EXTRACTLCS_UNIT);
		ListStringFactory w_lsfctB = new ListStringFactory(WHITESPC, EXTRACTLCS_UNIT);
		int w_rowsizA = w_lsfctA.calcRowSize(a);
		int w_rowsizB = w_lsfctB.calcRowSize(b);
		if ( w_rowsizA < MINWORDCNT || w_rowsizB < MINWORDCNT) {
			w_lsfctA = new ListStringFactory(WHITESPCPLUS, EXTRACTLCS_UNIT);
			w_rowsizA = w_lsfctA.calcRowSize(a);
			w_lsfctB = new ListStringFactory(WHITESPCPLUS, EXTRACTLCS_UNIT);
			w_rowsizB = w_lsfctB.calcRowSize(b);
		}

		if(w_rowsizA>w_rowsizB) {
			w_lsfctB.setRowSize(w_rowsizA);
		} else {
			w_lsfctA.setRowSize(w_rowsizB);
		}

		//List<String>
		List<String> alist = w_lsfctA.getLFSplittedStringList(null);

		List<String> blist = w_lsfctB.getLFSplittedStringList(null);
		
		int lpercent =  calcPercent(alist, blist, LCSresult);

		return lpercent;
		
		
	}

	/**
	 * calculate LCS  in character units
	 *
	 * @param ca
	 * @param cb
	 * @param clcs
	 * @return
	 */
	private int calcPercentChar(CharacterList ca, CharacterList cb, LcsCharacterList clcs) {
		LcsOnp<Character> onp = new LcsOnp<Character>(getLogger());

		int cpercent = onp.calcPercent(ca, cb, clcs);

		return cpercent;
	}

	/**
	 * compare String a with b.
	 * @param a
	 * @param b
	 * @param result - Longest Common Subsequence
	 * @return match rate 0-1000 (100.0 % * 10)
	 */
	int compare(String a, String b, LcsStringList result) {

		if(result==null) {
			result = new LcsStringList();
		}

		if(a==null) {
			a = "";
		}

		if(b==null) {
			b = "";
		}

		// response string size is less than MINCHARSIZE, then  calculate LCS  in character units
		if (a.length() < MINCHARSIZE && b.length() < MINCHARSIZE) {
			CharacterList ca = new CharacterList(a);
			CharacterList cb = new CharacterList(b);
			LcsCharacterList clcs = new LcsCharacterList();
			int cpercent = calcPercentChar(ca, cb,  clcs) ;
			result.initLcsCharacterList(clcs);
			return cpercent;
		}

		ListStringFactory lsfctA = new ListStringFactory("[\n]+", -1);
		ListStringFactory lsfctB = new ListStringFactory("[\n]+", -1);

		int rowsiza = lsfctA.calcRowSize(a);
		int origAsiz = lsfctA.getOrigRowSize();
		int rowsizb = lsfctB.calcRowSize(b);
		int origBsiz = lsfctB.getOrigRowSize();
		int origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;

		if(origMaxsiz<MINROWLENGTH) {
			ListStringFactory w_lsfctA = new ListStringFactory(WHITESPC, -1);
			ListStringFactory w_lsfctB = new ListStringFactory(WHITESPC, -1);
			int w_rowsiza = w_lsfctA.calcRowSize(a);
			int w_rowsizb = w_lsfctB.calcRowSize(b);

			if (w_rowsiza < MINWORDCNT || w_rowsizb < MINWORDCNT) {
				w_lsfctA = new ListStringFactory(WHITESPCPLUS, -1);
				w_rowsiza = w_lsfctA.calcRowSize(a);
				w_lsfctB = new ListStringFactory(WHITESPCPLUS, -1);
				w_rowsizb = w_lsfctB.calcRowSize(b);
			}

			lsfctA = w_lsfctA;
			lsfctB = w_lsfctB;
			rowsiza = w_rowsiza;
			rowsizb = w_rowsizb;
		}

		if(rowsiza>rowsizb) {
			lsfctB.setRowSize(rowsiza);
		} else {
			lsfctA.setRowSize(rowsizb);
		}
		List<String> alist = lsfctA.getLFSplittedStringList(null);

		List<String> blist = lsfctB.getLFSplittedStringList(null);

		if (log!=null) {
			log.debug("rowsize=" + lsfctA.getRowSize() + " alist.size=" + alist.size());
		}

		int lpercent =  calcPercent(alist, blist, result);
		if(log!=null) {
			log.debug("listpercent:" + lpercent);
		}
		//System.out.println("listpercent:" + lpercent);

		double dlpercent = 1000 - lpercent;

		return lpercent;
	}


}
