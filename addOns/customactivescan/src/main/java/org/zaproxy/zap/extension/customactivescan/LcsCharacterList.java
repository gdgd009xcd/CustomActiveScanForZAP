package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public class LcsCharacterList implements LcsBuilder<Character>{
	private StringBuilder builder = null;
	private StringBuilder da;
	private StringBuilder db;
	private StringBuilder[] diff = null;
	private boolean lcsReverse;
	private boolean diffAReverse;
	private boolean diffBReverse;
	private boolean ABreverse = false;

	
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
		if(ABreverse) {
			diff[0] = db;
			diff[1] = da;
		}else {
			diff[0] = da;
			diff[1] = db;
		}
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
		
		diff = new StringBuilder[2];
		if(ABreverse) {
			diff[0] = db;
			diff[1] = da;
		}else {
			diff[0] = da;
			diff[1] = db;
		}
	}

	/**
	 * append Character to list diffA.<BR>
	 * this method add Character to diffA in REVERSE ORDER.
	 * @param ta
	 */
	@Override
	public void appenddiffA(Character ta) {
		// TODO Auto-generated method stub
		
		diff[0].append(ta);
		
	}

	/**
	 * append Character to list diffB.<BR>
	 * this method add Character to diffB in REVERSE ORDER.
	 * @param tb
	 */
	@Override
	public void appenddiffB(Character tb) {
		// TODO Auto-generated method stub
		diff[1].append(tb);
		
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
