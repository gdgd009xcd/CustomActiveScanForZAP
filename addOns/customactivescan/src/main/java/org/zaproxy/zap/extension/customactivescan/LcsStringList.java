package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;


public class LcsStringList implements LcsBuilder<String>{

	private static final IteratorActionFactory<String> iteratorActionStringFactory = new IteratorActionFactory<>();
	private static final IteratorActionFactory<Integer> iteratorActionIntegerFactory = new IteratorActionFactory<>();
	List<String> strings;

	List<Integer> listLcsIdx_diffa;
	List<String> diffa;
	ArrayListWrapper<String> wrapperSourceA = null;


	List<Integer> listLcsIdx_diffb;
	List<String> diffb;
	ArrayListWrapper<String> wrapperSourceB = null;

	String lcschars;
	GenericArray<List<String>> diffArrayObject;
	List<String>[] diffArray;
	GenericArray<List<Integer>> lcsIdxArrayObject;
	List<Integer>[] lcsIdxArray;
	int diffArrayIndexA;
	int diffArrayIndexB;
	boolean lcsReverse;
	boolean ABreverse = false;
	boolean diffAreverse;
	boolean diffBreverse;
	String delimiter;
	int rowSize;
	boolean isInitializedByLcsCharacterList;

	LcsStringList(){
		clear();
	}

	public void initLcsCharacterList(LcsCharacterList cl,
									 ArrayListWrapper<String> wrapperSourceA,
									ArrayListWrapper<String> wrapperSourceB) {
		ABreverse = false;// ignore cl.ABreverse.
		// thus, diffArrayIndexA = 0 , diffArrayIndexB = 1.
		clear();

		isInitializedByLcsCharacterList = true;
		strings.add(cl.getLcsString());
		this.diffa.add(cl.getDiffAString());// diffArrayIndexA == 0
		this.diffb.add(cl.getDiffBString());// diffArrayIndexB == 1
		this.listLcsIdx_diffa = cl.getLcsIdxOnDiffA();// reverse oder.
		this.listLcsIdx_diffb = cl.getLcsIdxOnDiffB();// reverse order
		this.wrapperSourceA = wrapperSourceA;
		this.wrapperSourceB = wrapperSourceB;
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



	@Override
	public int size() {
		return strings.size();
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void clear() {
		strings = new ArrayList<>();
		diffa = new ArrayList<>();
		diffb = new ArrayList<>();
		lcschars = null;
		lcsReverse = false;
		diffAreverse = false;
		diffBreverse = false;
		this.wrapperSourceA = null;
		this.wrapperSourceB = null;
		isInitializedByLcsCharacterList = false;

		diffArrayObject = new GenericArray<>(strings, 2);
		diffArray = diffArrayObject.getArray();

		listLcsIdx_diffa = new ArrayList<>();
		listLcsIdx_diffb = new ArrayList<>();
		lcsIdxArrayObject = new GenericArray<>(listLcsIdx_diffa, 2);
		lcsIdxArray = lcsIdxArrayObject.getArray();

		setABreverseInternal();
		delimiter = null;
		rowSize = 1;

	}

	@Deprecated
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
	public void appendDiffA(String ta) {
		// TODO Auto-generated method stub
		//diffArray.get(0).add(ta);
		diffArray[0].add(ta);
	}

	/**
	 * append String to list diffB.<BR>
	 * this method add String to list in REVERSE ORDER.
	 * @param tb
	 */
	@Override
	public void appendDiffB(String tb) {
		// TODO Auto-generated method stub
		//diffArray.get(1).add(tb);
		diffArray[1].add(tb);
	}

	@Override
	public void appendLcsIdxOnDiffA(int idx) {
		//lcsIdxArray.get(0).add(idx);
		lcsIdxArray[0].add(idx);
	}
	@Override
	public void appendLcsIdxOnDiffB(int idx) {
		//lcsIdxArray.get(1).add(idx);
		lcsIdxArray[1].add(idx);
	}

	@Override
	public List<Integer> getLcsIdxOnDiffA() {
		return listLcsIdx_diffa;
	}

	@Override
	public List<Integer> getLcsIdxOnDiffB() {
		return listLcsIdx_diffb;
	}

	/**
	 * get LCS character position indexes of wrapperList
	 * @param wrapperList
	 * @param listLcsIndex
	 * @param reverseOrderOfListLcsIndex
	 * @return character start and end positions of LCS
	 */
	private List<StartEndPosition> getCharacterPositionListOfLcsIdxDiff(ArrayListWrapper<String> wrapperList,  List<Integer> listLcsIndex, boolean reverseOrderOfListLcsIndex) {
		IteratorAction<Integer> action = iteratorActionIntegerFactory.getGenericIteratorAction(listLcsIndex, reverseOrderOfListLcsIndex);
		Integer startIndex = null;
		Integer endIndex = null;
		int prevEndIndex = 0;
		int startIndexNonLcs = 0;
		int endIndexNonLcs = 0;

		List<StartEndPosition> listOfCharacterPosition = new ArrayList<>();
		int characterPosition = 0;
		for(startIndex = action.getNext(), endIndex = action.getNext();
			startIndex != null && endIndex !=null;
			startIndex = action.getNext(), endIndex = action.getNext()) {
			if (startIndex > prevEndIndex) {
				startIndexNonLcs = prevEndIndex;
				endIndexNonLcs = startIndex;
				int stringLengthNonLcs = getLengthOfConcatStringFromList(null,wrapperList, startIndexNonLcs, endIndexNonLcs);
				characterPosition += stringLengthNonLcs;
			}
			int startPosition = characterPosition;
			//listOfCharacterPosition.add(characterPosition);
			int stringLengthLcs = getLengthOfConcatStringFromList(null,wrapperList, startIndex, endIndex);
			characterPosition += stringLengthLcs;
			int endPosition = characterPosition;
			listOfCharacterPosition.add(new StartEndPosition(startPosition, endPosition));
			//listOfCharacterPosition.add(characterPosition);
			prevEndIndex = endIndex;
		}

		return listOfCharacterPosition;

	}

	public List<StartEndPosition> getCharacterPositionListOfLcsIdxDiffA() {
		boolean reverseOrder = diffAreverse;
		if (isInitializedByLcsCharacterList) {
			reverseOrder = true;
		}
		return getCharacterPositionListOfLcsIdxDiff(this.wrapperSourceA, listLcsIdx_diffa, reverseOrder);
	}

	public List<StartEndPosition> getCharacterPositionListOfLcsIdxDiffB() {
		boolean reverseOrder = diffBreverse;
		if (isInitializedByLcsCharacterList) {
			reverseOrder = true;
		}
		return getCharacterPositionListOfLcsIdxDiff(this.wrapperSourceB, listLcsIdx_diffb, reverseOrder);
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
		StringBuffer lcsString = new StringBuffer();
		if (list != null) {
			//IteratorAction<String> action = getIteratorAction(list, reverse);
			IteratorAction<String> action = iteratorActionStringFactory.getGenericIteratorAction(list, reverse);
			for (String data = action.getNext(); data != null; data = action.getNext()) {
				//if (!lcsString.isEmpty()) {
				if (lcsString.length()>0) {
					lcsString.append(delimiter);
					//lcsString += delimiter;
				}
				//lcsString += data;
				lcsString.append(data);
			}
		}
		return lcsString.toString();
	}

	/**
	 * concatenate Strings between startIndex and endIndex in wrapperList
	 * @param delimiter
	 * @param wrapperList
	 * @param startIndex
	 * @param endIndex
	 * @return
	 */
	 public String concatStringFromList(String delimiter, ArrayListWrapper<String> wrapperList, int startIndex, int endIndex) {
		if (delimiter == null) {
			delimiter = "";
		}
		StringBuffer lcsString = new StringBuffer();
		if (wrapperList != null) {
			int endCount;
			String data;
			IteratorAction<String> action = iteratorActionStringFactory.getGenericIteratorAction(wrapperList.getOriginalList(),startIndex, wrapperList.isOriginalReverseOrder());
			for (data = action.getNext(),endCount = startIndex;
				 data != null && endCount < endIndex ;
				 data = action.getNext(), endCount++) {
				//if (!lcsString.isEmpty()) {
				if (lcsString.length()>0) {
					lcsString.append(delimiter);
					//lcsString += delimiter;
				}
				//lcsString += data;
				lcsString.append(data);
			}
		}
		return lcsString.toString();
	}

	/**
	 * get total length of Strings between startIndex and end Index in wrapperList
	 * @param delimiter
	 * @param wrapperList
	 * @param startIndex
	 * @param endIndex
	 * @return
	 */
	public int getLengthOfConcatStringFromList(String delimiter, ArrayListWrapper<String> wrapperList, int startIndex, int endIndex) {
		if (delimiter == null) {
			delimiter = "";
		}
		int totalLength = 0;
		if (wrapperList != null) {
			int endCount;
			String data;
			IteratorAction<String> action = iteratorActionStringFactory.getGenericIteratorAction(wrapperList.getOriginalList(),startIndex, wrapperList.isOriginalReverseOrder());
			for (data = action.getNext(),endCount = startIndex;
				 data != null && endCount < endIndex ;
				 data = action.getNext(), endCount++) {
				//if (!lcsString.isEmpty()) {
				if (totalLength > 0) {
					totalLength += delimiter.length();
					//lcsString += delimiter;
				}
				//lcsString += data;
				totalLength += data.length();
			}
		}
		return totalLength;
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
		setABreverseInternal();
	}

	private void setABreverseInternal() {
		if(ABreverse) {
			//diffs[0] = diffb;
			//diffs[1] = diffa;
			diffArrayIndexA = 1;
			diffArrayIndexB = 0;
		}else {
			//diffs[0] = diffa;
			//diffs[1] = diffb;
			diffArrayIndexA = 0;
			diffArrayIndexB = 1;
		}
		diffArrayObject.set(diffArrayIndexA, diffa);
		diffArrayObject.set(diffArrayIndexB, diffb);
		lcsIdxArrayObject.set(diffArrayIndexA, listLcsIdx_diffa);
		lcsIdxArrayObject.set(diffArrayIndexB, listLcsIdx_diffb);
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

	public void setOriginalDiffA(List<String> diffa, boolean isReverseOrder) {
		if (ABreverse) {
			this.diffBreverse = isReverseOrder;
			this.diffb = diffa;
		} else {
			this.diffAreverse = isReverseOrder;
			this.diffa = diffa;
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

	public void setOriginalDiffB(List<String> diffb, boolean isReverseOrder) {
		if (ABreverse) {
			this.diffAreverse = isReverseOrder;
			this.diffa = diffb;
		} else {
			this.diffBreverse = isReverseOrder;
			this.diffb = diffb;
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

	@Override
	public void setWrapperSourceA(ArrayListWrapper<String> wrapperSourceA) {
		if (ABreverse) {
			this.wrapperSourceB = wrapperSourceA;
		} else {
			this.wrapperSourceA = wrapperSourceA;
		}
	}

	@Override
	public void setWrapperSourceB(ArrayListWrapper<String> wrapperSourceB) {
		if (ABreverse) {
			this.wrapperSourceA = wrapperSourceB;
		} else {
			this.wrapperSourceB = wrapperSourceB;
		}
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
	@Deprecated
	public void obsolete_setLcsChars(String c) {
		lcschars = c;
	}

	/* obsolete */
	@Deprecated
	public String obsolete_getLcsChars() {
		return lcschars;
	}

}
