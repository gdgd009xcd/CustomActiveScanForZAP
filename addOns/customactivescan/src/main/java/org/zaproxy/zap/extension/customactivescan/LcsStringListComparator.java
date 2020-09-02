package org.zaproxy.zap.extension.customactivescan;

import org.apache.log4j.Logger;

import java.util.List;

public class LcsStringListComparator extends LcsOnp<String>{
	static Logger log = Logger.getLogger(LcsStringListComparator.class);

	int MINROWLENGTH = 500; // if contents line count < MINROWLENGTH, then split contents by whitespace.
	int EXTRACTLCS_UNIT = 500000; // extractLCS row unit.
	
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

		ListStringFactory w_lsfctA = new ListStringFactory("[ \r\t\n]+", EXTRACTLCS_UNIT);
		ListStringFactory w_lsfctB = new ListStringFactory("[ \r\t\n]+", EXTRACTLCS_UNIT);
		int w_rowsizA = w_lsfctA.calcRowSize(a);
		int w_origAsiz = w_lsfctA.getOrigRowSize();
		int w_rowsizB = w_lsfctB.calcRowSize(b);
		int w_origBsiz = w_lsfctB.getOrigRowSize();

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
	
	int calcPercentChar(CharacterList ca, CharacterList cb, LcsCharacterList clcs) {
		LcsOnp<Character> onp = new LcsOnp<Character>(getLogger());
		LcsCharacterList cresult = new LcsCharacterList();
		
		int cpercent = onp.calcPercent(ca, cb, clcs);
		{
			String diffCA = cresult.getDiffAString();
			int sa = diffCA.length();
			String diffCB = cresult.getDiffBString();
			int sb = diffCB.length();
			//System.out.println("diffCA[" + diffCA.substring(0, sa>50?50:sa) + "...]");
			//System.out.println("diffCB[" + diffCB.substring(0, sb>50?50:sb) + "...]");
			String lcsstr = cresult.getLCS().getString();
			int lcssiz = lcsstr.length();
			String samelcs = lcsstr.substring(0, lcssiz>50?50:lcssiz);
			//System.out.println("lcs[" + samelcs + "...]");
		}
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

		ListStringFactory lsfctA = new ListStringFactory("[\n]+", -1);
		ListStringFactory lsfctB = new ListStringFactory("[\n]+", -1);

		int rowsiza = lsfctA.calcRowSize(a);
		int origAsiz = lsfctA.getOrigRowSize();
		int rowsizb = lsfctB.calcRowSize(b);
		int origBsiz = lsfctB.getOrigRowSize();
		int origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;

		if(origMaxsiz<MINROWLENGTH) {
			ListStringFactory w_lsfctA = new ListStringFactory("[ \r\t\n]+", -1);
			ListStringFactory w_lsfctB = new ListStringFactory("[ \r\t\n]+", -1);
			int w_rowsiza = w_lsfctA.calcRowSize(a);
			int w_origAsiz = w_lsfctA.getOrigRowSize();
			int w_rowsizb = w_lsfctB.calcRowSize(b);
			int w_origBsiz = w_lsfctB.getOrigRowSize();
			origMaxsiz = w_origAsiz>w_origBsiz?w_origAsiz:w_origBsiz;
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

		log.debug("rowsize=" + lsfctA.getRowSize() + " alist.size=" + alist.size());
		int lpercent =  calcPercent(alist, blist, result);
		if(log!=null) {
			log.debug("listpercent:" + lpercent);
		}
		//System.out.println("listpercent:" + lpercent);

		double dlpercent = 1000 - lpercent;

		return lpercent;
	}


}
