package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;

public class LcsStringList implements LcsBuilder<String>{
	List<String> strings;
	List<String> diffa;
	List<String> diffb;
	String lcschars;
	Object[] diffs = null;
	boolean lcsReverse;
	boolean ABreverse = false;
	boolean diffAreverse;
	boolean diffBreverse;
	String delimiter;
	int rowSize;

	LcsStringList(){
		clear();
	}

	public void initLcsCharacterList(LcsCharacterList cl) {
		clear();
		strings = new ArrayList<>();
		strings.add(cl.getLcsString());
		diffa = new ArrayList<>();
		diffb = new ArrayList<>();
		diffa.add(cl.getDiffAString());
		diffb.add(cl.getDiffBString());
	}

	@Override
	public void append(String s) {
		strings.add(s);
	}
	
	/**
	 * get String of Longest Common Subsequence from two strings in ORIGINAL ORDER.
	 *
	 * @return
	 */
	public String getLCSString(String delimiter){
		return getStringFromList(delimiter, strings, lcsReverse);
	}

	static private IteratorAction<String> getIteratorAction(List<String> stringList, boolean reverse) {
		if (reverse) {
			return new IteratorAction<String>() {
				private ListIterator<String> it = stringList.listIterator(stringList.size());

				@Override
				public void rewind() {
					it = stringList.listIterator(stringList.size());
				}

				@Override
				public String getNext() {
					if (it.hasPrevious()) return it.previous();
					return null;
				}
			};
		}
		return new IteratorAction<String>() {
			private ListIterator<String> it = stringList.listIterator();

			@Override
			public void rewind() {
				it = stringList.listIterator();
			}

			@Override
			public String getNext() {
				if (it.hasNext()) return it.next();
				return null;
			}
		};
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
		lcsReverse = false;
		diffAreverse = false;
		diffBreverse = false;
		diffs = new Object[2];
		if(ABreverse) {
			diffs[0] = diffb;
			diffs[1] = diffa;
		}else {
			diffs[0] = diffa;
			diffs[1] = diffb;
		}
		delimiter = null;
		rowSize = 1;

	}
	
	@SuppressWarnings("unchecked")
    public ArrayList<String> cast(Object obj) {
        return (ArrayList<String>) obj;
    }

	/**
	 * append String to list diffA.<BR>
	 * this method add String to list in REVERSE ORDER.
	 * @param ta
	 */
	@Override
	public void appenddiffA(String ta) {
		// TODO Auto-generated method stub
		cast(diffs[0]).add(ta);
	}

	/**
	 * append String to list diffB.<BR>
	 * this method add String to list in REVERSE ORDER.
	 * @param tb
	 */
	@Override
	public void appenddiffB(String tb) {
		// TODO Auto-generated method stub
		cast(diffs[1]).add(tb);
	}

	/**
	 * get String from Diffa in "Original Order".
	 *
	 * @param delimiter
	 * @return
	 */
	public String getDiffAString(String delimiter) {
		return getStringFromList(delimiter, diffa, diffAreverse);
	}

	/**
	 * get String from DiffB in "Original Order".
	 * @param delimiter
	 * @return
	 */
	public String getDiffBString(String delimiter) {
		return getStringFromList(delimiter, diffb, diffBreverse);
	}

	static public String getStringFromList(String delimiter, List<String> list, boolean reverse) {
		if (delimiter == null) {
			delimiter = "";
		}
		String lcsString = "";
		if (list != null) {
			IteratorAction<String> action = getIteratorAction(list, reverse);
			for (String data = action.getNext(); data != null; data = action.getNext()) {
				if (!lcsString.isEmpty()) {
					lcsString += delimiter;
				}
				lcsString += data;
			}
		}
		return lcsString;
	}

	@Override
	public void setReverse() {
		// TODO Auto-generated method stub
		lcsReverse = true;
		diffAreverse = true;
		diffBreverse = true;
	}

	@Override
	public boolean isReverseLCS() {
		return lcsReverse;
	}

	@Override
	public boolean isReverseDiffA() {
		return this.diffAreverse;
	}

	@Override
	public boolean isReverseDiffB() {
		return this.diffBreverse;
	}

	@Override
	public void setABreverse(boolean b) {
		ABreverse = b;
		if(ABreverse) {
			diffs[0] = diffb;
			diffs[1] = diffa;
		}else {
			diffs[0] = diffa;
			diffs[1] = diffb;
		}
	}

	@Override
	public String getLcsElement(int index) {
		return strings.get(index);
	}

	public List<String> getOriginalLcs() {
		return this.strings;
	}

	@Override
	public String getDiffAElement(int index) {
		return diffa.get(index);
	}

	@Override
	public void setOriginalDiffA(ArrayListWrapper<String> wrapperDiffA) {
		if (ABreverse) {
			this.diffBreverse = wrapperDiffA.isOriginalReverseOrder();
			this.diffb = wrapperDiffA.getOriginalList();
		} else {
			this.diffAreverse = wrapperDiffA.isOriginalReverseOrder();
			this.diffa = wrapperDiffA.getOriginalList();
		}
	}


	public List<String> getOriginalDiffA() {
		return diffa;
	}

	@Override
	public String getDiffBElement(int index) {
		return diffb.get(index);
	}

	@Override
	public void setOriginalDiffB(ArrayListWrapper<String> wrapperDiffB) {
		if (ABreverse) {
			this.diffAreverse = wrapperDiffB.isOriginalReverseOrder();
			this.diffa = wrapperDiffB.getOriginalList();
		} else {
			this.diffBreverse = wrapperDiffB.isOriginalReverseOrder();
			this.diffb = wrapperDiffB.getOriginalList();
		}
	}


	public List<String> getOriginalDiffB() {
		return diffb;
	}

	@Override
	public int getDiffASize() {
		return diffa.size();
	}

	@Override
	public int getDiffBSize() {
		return diffb.size();
	}

	public void setDelimiter(String delimiter) {
		this.delimiter = delimiter;
	}

	public String getDelimiter() {
		return this.delimiter;
	}

	public boolean hasSameDelimiter(LcsStringList otherLcs) {
		String otherDelimiter = otherLcs != null ? otherLcs.getDelimiter() : null;
		if (this.delimiter != null && otherDelimiter != null) {
			return this.delimiter.equals(otherDelimiter);
		} else if(this.delimiter == otherDelimiter) {
			return true;
		}
		return false;
	}

	public boolean hasSameDelimiter(ArrayListWrapper<String> listWrapper) {
		String otherDelimiter = listWrapper!=null? listWrapper.getDelimiter() : null;
		if (this.delimiter != null && otherDelimiter != null) {
			return this.delimiter.equals(otherDelimiter);
		} else if(this.delimiter == otherDelimiter) {
			return true;
		}
		return false;
	}

	public void setRowSize(int rowSize) {
		this.rowSize = rowSize;
	}

	public int getRowSize() {
		return this.rowSize;
	}

	public boolean hasSameRowSize(LcsStringList otherLcs) {
		int otherRowSize = otherLcs != null ? otherLcs.getRowSize() : -1;
		if (this.rowSize == otherRowSize) return true;
		return false;
	}

	public boolean hasSameRowSize(ArrayListWrapper<String> listWrapper) {
		int otherRowSize = listWrapper != null ? listWrapper.getRowSize() : -1 ;
		if (this.rowSize == otherRowSize) {
			return true;
		}
		return false;
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
