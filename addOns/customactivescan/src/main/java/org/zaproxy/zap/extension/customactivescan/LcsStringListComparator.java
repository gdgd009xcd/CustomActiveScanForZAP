package org.zaproxy.zap.extension.customactivescan;

import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class LcsStringListComparator extends LcsOnp<String>{
	static Logger log = Logger.getLogger(LcsStringListComparator.class);

	int MINROWLENGTH = 500; // if contents line count < MINROWLENGTH, then split contents by whitespace.
	int EXTRACTLCS_UNIT = 500000; // extractLCS row unit.
	int MINWORDCNT = 50; // if word count of splitted response fewer than this value, then split again with WHITESPCPLUS delimiter.

	// default split delimiter.
	String CRLF = "[\r\n]+";

	// next precise split delimiter.
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

		String delimiter = WHITESPC;
		int rowSize = 1;
		ListStringFactory w_lsfctA = new ListStringFactory(delimiter, EXTRACTLCS_UNIT);
		ListStringFactory w_lsfctB = new ListStringFactory(delimiter, EXTRACTLCS_UNIT);
		int w_rowsizA = w_lsfctA.calcRowSize(a);
		int w_rowsizB = w_lsfctB.calcRowSize(b);
		int origSizeA = w_lsfctA.getOrigSize();
		int origSizeB = w_lsfctB.getOrigSize();
		int origSizeMax = origSizeA > origSizeB ? origSizeA : origSizeB;
		if (origSizeMax < MINWORDCNT) {
			delimiter = WHITESPCPLUS;
			w_lsfctA = new ListStringFactory(delimiter, EXTRACTLCS_UNIT);
			w_rowsizA = w_lsfctA.calcRowSize(a);
			w_lsfctB = new ListStringFactory(delimiter, EXTRACTLCS_UNIT);
			w_rowsizB = w_lsfctB.calcRowSize(b);
		}

		if(w_rowsizA>w_rowsizB) {
			w_lsfctB.setRowSize(w_rowsizA);
			rowSize = w_rowsizA;
		} else {
			w_lsfctA.setRowSize(w_rowsizB);
			rowSize = w_rowsizB;
		}

		//List<String>
		List<String> alist = w_lsfctA.getLFSplittedStringList(null);
		ArrayListWrapperFactory actionFactoryA = new ArrayListWrapperFactory(alist, false, rowSize, delimiter);

		List<String> blist = w_lsfctB.getLFSplittedStringList(null);
		ArrayListWrapperFactory actionFactoryB = new ArrayListWrapperFactory(blist, false, rowSize, delimiter);


		LCSresult.setRowSize(rowSize);
		LCSresult.setDelimiter(delimiter);

		int lpercent =  calcPercent(
				actionFactoryA.createArrayListWrapper(),
				actionFactoryB.createArrayListWrapper(),
				LCSresult);

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
	private int calcPercentChar(ArrayListWrapper<Character> ca, ArrayListWrapper<Character> cb, LcsCharacterList clcs) {
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
	int compare(String a, String b, LcsStringList result) throws Exception{

		if(result==null) {
			throw new Exception("Do not specify a NULL value for the LcsStringList");
		}

		if(a==null) {
			a = "";
		}

		if(b==null) {
			b = "";
		}

		int rowSize = 1;
		String delimiter = CRLF;
		ListStringFactory lsfctA = new ListStringFactory(delimiter, -1);
		ListStringFactory lsfctB = new ListStringFactory(delimiter, -1);

		int rowsiza = lsfctA.calcRowSize(a);
		int origAsiz = lsfctA.getOrigSize();
		int rowsizb = lsfctB.calcRowSize(b);
		int origBsiz = lsfctB.getOrigSize();
		int origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;

		if(origMaxsiz<MINROWLENGTH) {
			delimiter = WHITESPC;
			ListStringFactory w_lsfctA = new ListStringFactory(delimiter, -1);
			ListStringFactory w_lsfctB = new ListStringFactory(delimiter, -1);
			int w_rowsiza = w_lsfctA.calcRowSize(a);
			int w_rowsizb = w_lsfctB.calcRowSize(b);
			origAsiz = w_lsfctA.getOrigSize();
			origBsiz = w_lsfctB.getOrigSize();
			origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;
			if (origMaxsiz < MINWORDCNT) {
				delimiter = WHITESPCPLUS;
				w_lsfctA = new ListStringFactory(delimiter, -1);
				w_rowsiza = w_lsfctA.calcRowSize(a);
				w_lsfctB = new ListStringFactory(delimiter, -1);
				w_rowsizb = w_lsfctB.calcRowSize(b);
			}


			lsfctA = w_lsfctA;
			lsfctB = w_lsfctB;
			rowsiza = w_rowsiza;
			rowsizb = w_rowsizb;
		}

		if (log.isDebugEnabled()) {
			PrintableString printableString = new PrintableString(delimiter);

			log.debug("compare delimiter["
					+ printableString.convert(50)
					+ "] origMaxsiz[" + origMaxsiz + "] < "
					+ (origMaxsiz < MINWORDCNT ? "MINWORDCNT(" + MINWORDCNT + ")" : "MINROWLENGTH(" + MINROWLENGTH + ")")
			);
		}
		if(rowsiza>rowsizb) {
			lsfctB.setRowSize(rowsiza);
			rowSize = rowsiza;
		} else {
			lsfctA.setRowSize(rowsizb);
			rowSize = rowsizb;
		}
		List<String> alist = lsfctA.getLFSplittedStringList(null);
		ArrayListWrapperFactory actionFactoryA = new ArrayListWrapperFactory(alist, false, rowSize, delimiter);

		List<String> blist = lsfctB.getLFSplittedStringList(null);
		ArrayListWrapperFactory actionFactoryB = new ArrayListWrapperFactory(blist, false, rowSize, delimiter);

		if (log!=null) {
			log.debug("rowsize=" + lsfctA.getRowSize() + " alist.size=" + alist.size());
			ArrayListWrapper<String> actionA = actionFactoryA.createArrayListWrapper();

			log.debug("action size=" + actionA.size());
		}

		result.setRowSize(rowSize);
		result.setDelimiter(delimiter);

		int lpercent =  calcPercent(
				actionFactoryA.createArrayListWrapper(),
				actionFactoryB.createArrayListWrapper(),
				result);
		if(log!=null) {
			log.debug("listpercent:" + lpercent);
		}

		return lpercent;
	}

	public int compare(ArrayListWrapper<String> alist, ArrayListWrapper<String> blist, LcsStringList result) throws Exception {
		if(result==null) {
			throw new Exception("Do not specify a NULL value for the LcsStringList");
		}

		String aDelimiter = alist.getDelimiter()==null?"":alist.getDelimiter();
		String bDelimiter = blist.getDelimiter()==null?"":blist.getDelimiter();
		if (alist.getRowSize() != blist.getRowSize() || !aDelimiter.equals(bDelimiter)) {
			String aString = LcsStringList.getStringFromList("", alist.getOriginalList(), alist.isOriginalReverseOrder());
			String bString = LcsStringList.getStringFromList("", blist.getOriginalList(), blist.isOriginalReverseOrder());
			return compare(aString, bString, result);
		}
		if (log.isDebugEnabled()) {
			String delimiter = aDelimiter;
			PrintableString printableString = new PrintableString(delimiter);

			int origAsiz = alist.size();
			int origBsiz = blist.size();
			int origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;
			log.debug("compare delimiter["
					+ printableString.convert(50)
					+ "] origMaxsiz[" + origMaxsiz + "] < "
					+ (origMaxsiz < MINWORDCNT ? "MINWORDCNT(" + MINWORDCNT + ")" : "MINROWLENGTH(" + MINROWLENGTH + ")")
			);
		}
		int lpercent =  calcPercent(
				alist,
				blist,
				result);
		if(log!=null) {
			log.debug("listpercent:" + lpercent);
		}

		return lpercent;
	}

	/**
	 * compare List&lt;String&gt; with String
	 *
	 * @param listWrapperA
	 * @param b
	 * @param result
	 * @return
	 * @throws Exception
	 */
	int compare(ArrayListWrapper<String> listWrapperA, String b, LcsStringList result) throws Exception{

		if(result==null) {
			throw new Exception("Do not specify a NULL value for the LcsStringList");
		}

		if(b==null) {
			b = "";
		}

		if(listWrapperA==null) {
			String a = "";
			return compare(a, b, result);
		}



		int rowSize = 1;
		String delimiter = listWrapperA.getDelimiter();
		ListStringFactory lsfctB = new ListStringFactory(delimiter, -1);

		int rowsiza = listWrapperA.getRowSize();
		int origAsiz = listWrapperA.size();
		int rowsizb = lsfctB.calcRowSize(b);
		int origBsiz = lsfctB.getOrigSize();
		int origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;

		ArrayListWrapperFactory actionFactoryA = null;

		if(origMaxsiz<MINROWLENGTH) {
			delimiter = WHITESPC;
			String a = LcsStringList.getStringFromList("", listWrapperA.getOriginalList(), listWrapperA.isOriginalReverseOrder());
			ListStringFactory lsfctA = new ListStringFactory(delimiter, -1);
			lsfctB = new ListStringFactory(delimiter, -1);
			rowsiza = lsfctA.calcRowSize(a);
			rowsizb = lsfctB.calcRowSize(b);
			origAsiz = lsfctA.getOrigSize();
			origBsiz = lsfctB.getOrigSize();
			origMaxsiz = origAsiz>origBsiz?origAsiz:origBsiz;
			if (origMaxsiz < MINWORDCNT) {
				delimiter = WHITESPCPLUS;
				lsfctA = new ListStringFactory(delimiter, -1);
				rowsiza = lsfctA.calcRowSize(a);
				lsfctB = new ListStringFactory(delimiter, -1);
				rowsizb = lsfctB.calcRowSize(b);
			}

			if(rowsiza>rowsizb) {
				lsfctB.setRowSize(rowsiza);
				rowSize = rowsiza;
			} else {
				lsfctA.setRowSize(rowsizb);
				rowSize = rowsizb;
			}
			List<String> walist = lsfctA.getLFSplittedStringList(null);
			actionFactoryA = new ArrayListWrapperFactory(
					walist,
					false,
					rowSize,
					delimiter);
		} else {

			if (rowsiza > rowsizb) {
				lsfctB.setRowSize(rowsiza);
				rowSize = rowsiza;
			} else {
				String a = LcsStringList.getStringFromList(
						"",
						listWrapperA.getOriginalList(),
						listWrapperA.isOriginalReverseOrder());
				ListStringFactory lsfctA = new ListStringFactory(delimiter, -1);
				lsfctA.calcRowSize(a);
				lsfctA.setRowSize(rowsizb);
				rowSize = rowsizb;
				List<String> walist = lsfctA.getLFSplittedStringList(null);
				actionFactoryA = new ArrayListWrapperFactory(walist, false, rowSize, delimiter);
			}
		}


		if (actionFactoryA != null) {
			listWrapperA = actionFactoryA.createArrayListWrapper();
		}
		List<String> blist = lsfctB.getLFSplittedStringList(null);
		ArrayListWrapperFactory actionFactoryB = new ArrayListWrapperFactory(blist, false, rowSize, delimiter);

		result.setRowSize(rowSize);
		result.setDelimiter(delimiter);

		if (log.isDebugEnabled()) {
			PrintableString printableString = new PrintableString(delimiter);

			log.debug("compare delimiter["
					+ printableString.convert(50)
					+ "] origMaxsiz[" + origMaxsiz + "] < "
					+ (origMaxsiz < MINWORDCNT ? "MINWORDCNT(" + MINWORDCNT + ")" : "MINROWLENGTH(" + MINROWLENGTH + ")")
			);
		}
		int lpercent =  calcPercent(
				listWrapperA,
				actionFactoryB.createArrayListWrapper(),
				result);
		if(log!=null) {
			log.debug("listpercent:" + lpercent);
		}

		return lpercent;
	}

	/**
	 * compare Strings character by character
	 *
	 * @param a
	 * @param b
	 * @param result - Longest Common Subsequence
	 * @return match rate 0-1000 (100.0 % * 10)
	 */
	int compareStringByChar(String a, String b, LcsStringList result) throws Exception {

		if(result==null) {
			throw new Exception("Do not specify a NULL value for the LcsStringList");
		}

		if (a == null) {
			a = "";
		}

		if (b == null) {
			b = "";
		}

		//CharacterList ca = new CharacterList(a);
		//CharacterList cb = new CharacterList(b);
		final String stringA = a;
		final String stringB = b;
		ArrayListWrapper<Character> charListWrapperA = new ArrayListWrapper<>() {
			@Override
			public int size() {
				return stringA.length();
			}

			@Override
			public Character get(int index) {
				return stringA.charAt(index);
			}

			@Override
			public boolean isOriginalReverseOrder() {
				return false;
			}

			@Override
			public List<Character> getOriginalList() {
				char[] charArray = stringA.toCharArray();
				List<Character> clist = new ArrayList<>();
				for(char c: charArray) {
					clist.add(c);
				}
				return clist;
			}

			@Override
			public int getRowSize() {
				return 0;
			}

			@Override
			public String getDelimiter() {
				return null;
			}
		};

		ArrayListWrapper<Character> charListWrapperB = new ArrayListWrapper<>() {
			@Override
			public int size() {
				return stringB.length();
			}

			@Override
			public Character get(int index) {
				return stringB.charAt(index);
			}

			@Override
			public boolean isOriginalReverseOrder() {
				return false;
			}

			@Override
			public List<Character> getOriginalList() {
				char[] charArray = stringB.toCharArray();
				List<Character> clist = new ArrayList<>();
				for(char c: charArray) {
					clist.add(c);
				}
				return clist;
			}

			@Override
			public int getRowSize() {
				return 0;
			}

			@Override
			public String getDelimiter() {
				return null;
			}
		};

		LcsCharacterList clcs = new LcsCharacterList();
		int cpercent = calcPercentChar(charListWrapperA, charListWrapperB, clcs);
		result.initLcsCharacterList(clcs);
		return cpercent;
	}
}
