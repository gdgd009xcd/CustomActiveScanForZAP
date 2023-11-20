package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.List;

public class LcsCharacterList implements LcsBuilder<Character>{
	private StringBuilder builder = null;
	List<Integer> listLcsIdx_diffa;
	private StringBuilder da;
	List<Integer> listLcsIdx_diffb;
	GenericArray<List<Integer>> lcsIdxArrayObject;
	List<Integer>[] lcsIdxArray;
	int diffArrayIndexA;
	int diffArrayIndexB;
	private StringBuilder db;
	private StringBuilder[] diffArray = null;
	private boolean lcsReverse;
	private boolean diffAReverse;
	private boolean diffBReverse;
	private boolean ABreverse = false;
	private int aPercent;
	private int bPercent;

	
	LcsCharacterList(){
		clear();
	}
	
	@Override
	public void setReverse() {
		lcsReverse = true;
		diffAReverse = true;
		diffBReverse = true;
	}

	@Override
	public boolean isReverseLCS() {
		return lcsReverse;
	}

	@Override
	public boolean isReverseDiffA() {
		return this.diffAReverse;
	}

	@Override
	public boolean isReverseDiffB() {
		return this.diffBReverse;
	}

	@Override
	public void setABreverse(boolean b) {
		ABreverse = b;
		setABreverseInternal();
	}

	@Override
	public Character getLcsElement(int index) {
		try {
			char c = builder.charAt(index);
			return Character.valueOf(c);
		} catch (Exception ex) {

		}
		return null;
	}

	@Override
	public Character getDiffAElement(int index) {
		try {
			char c = da.charAt(index);
			return Character.valueOf(c);
		} catch (Exception ex) {

		}
		return null;
	}

	@Override
	public void setOriginalDiffA(ArrayListWrapper<Character> wrapperDiffA) {
		if (ABreverse) {
			this.diffBReverse = wrapperDiffA.isOriginalReverseOrder();
			this.db.append(wrapperDiffA.getOriginalList());
		} else {
			this.diffAReverse = wrapperDiffA.isOriginalReverseOrder();
			this.da.append(wrapperDiffA.getOriginalList());
		}
	}

	@Override
	public Character getDiffBElement(int index) {
		try {
			char c = db.charAt(index);
			return Character.valueOf(c);
		} catch (Exception ex) {

		}
		return null;
	}

	@Override
	public void setOriginalDiffB(ArrayListWrapper<Character> wrapperDiffB) {
		if (ABreverse) {
			this.diffAReverse = wrapperDiffB.isOriginalReverseOrder();
			this.da.append(wrapperDiffB.getOriginalList());
		} else {
			this.diffBReverse = wrapperDiffB.isOriginalReverseOrder();
			this.db.append(wrapperDiffB.getOriginalList());
		}
	}

	@Override
	public int getDiffASize() {
		return da.length();
	}

	@Override
	public int getDiffBSize() {
		return db.length();
	}

	@Override
	public void setWrapperSourceA(ArrayListWrapper<Character> wrapperSourceA) {
		if (ABreverse) {

		} else {

		}
	}

	@Override
	public void setWrapperSourceB(ArrayListWrapper<Character> wrapperSourceB) {

	}

	@Override
	public void setPercents(int aPercent, int bPercent) {
		this.aPercent = aPercent;
		this.bPercent = bPercent;
	}

	@Override
	public int getApercent() {
		return this.aPercent;
	}

	@Override
	public int getBpercent() {
		return this.bPercent;
	}

	/**
	 * add character to builder as LCS.
	 * add characters in REVERSE ORDER.
	 * @param c
	 */
	@Override
	public void append(Character c) {
		builder.append(c);
	}

	/**
	 * get String from LCS in "Original Order".
	 * @return
	 */
	public String getLcsString() {
		return lcsReverse?builder.reverse().toString():builder.toString();
	}
	
	@Override
	public int size() {
		return builder.length();
	}
	
	@Override
	public void clear() {
		builder = new StringBuilder();
		da = new StringBuilder();
		db = new StringBuilder();
		lcsReverse = false;
		diffAReverse = false;
		diffBReverse = false;

		listLcsIdx_diffa = new ArrayList<>();
		listLcsIdx_diffb = new ArrayList<>();
		lcsIdxArrayObject = new GenericArray<>(listLcsIdx_diffa, 2);
		lcsIdxArray = lcsIdxArrayObject.getArray();
		diffArray = new StringBuilder[2];
		setABreverseInternal();
		this.aPercent = -1;
		this.bPercent = -1;
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
		diffArray[diffArrayIndexA] = da;
		diffArray[diffArrayIndexB] = db;
		lcsIdxArrayObject.set(diffArrayIndexA, listLcsIdx_diffa);
		lcsIdxArrayObject.set(diffArrayIndexB, listLcsIdx_diffb);
	}
	/**
	 * append Character to list diffA.<BR>
	 * this method add Character to diffA in REVERSE ORDER.
	 * @param ta
	 */
	@Override
	public void appendDiffA(Character ta) {
		// TODO Auto-generated method stub
		//diff[0].append(ta);
		diffArray[0].append(ta);
		
	}

	/**
	 * append Character to list diffB.<BR>
	 * this method add Character to diffB in REVERSE ORDER.
	 * @param tb
	 */
	@Override
	public void appendDiffB(Character tb) {
		// TODO Auto-generated method stub
		//diff[1].append(tb);
		diffArray[1].append(tb);
		
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
	 * get String from DiffA in "Original Order".
	 * @return
	 */
	public String getDiffAString() {
		return diffAReverse ? da.reverse().toString() : da.toString();
	}

	/**
	 * get String from DiffB in "Original Order".
	 * @return
	 */
	public String getDiffBString() {
		return diffBReverse ? db.reverse().toString() : db.toString();
	}

	public boolean isABreverse() {
		return this.ABreverse;
	}
}
