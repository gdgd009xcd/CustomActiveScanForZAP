package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public class LcsCharacterList implements LcsBuilder<Character>{
	private StringBuilder builder = null;
	private StringBuilder da;
	private StringBuilder db;
	private StringBuilder[] diff = null;
	private boolean reverse;
	private boolean ABreverse = false;

	
	LcsCharacterList(){
		clear();
	}
	
	@Override
	public void setReverseLCS() {
		reverse = true;
	}
	
	@Override
	public void setABreverse(boolean b) {
		ABreverse = b;
	}
	
	@Override
	public void append(Character c) {
		builder.append(c);
	}
	
	@Override
	public void add(int index, Character c) {
		builder.insert(index, c);
	}
	
	@Override
	public CharacterList getLCS(){
		CharacterList clist = new CharacterList(reverse?builder.reverse().toString():builder.toString());//stored reverse order.
		return clist;
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
		reverse = false;
		
		diff = new StringBuilder[2];
		if(ABreverse) {
			diff[0] = db;
			diff[1] = da;
		}else {
			diff[0] = da;
			diff[1] = db;
		}
	}

	@Override
	public void appenddiffA(Character ta) {
		// TODO Auto-generated method stub
		
		diff[0].append(ta);
		
	}
	
	@Override
	public void appenddiffB(Character tb) {
		// TODO Auto-generated method stub
		diff[1].append(tb);
		
	}

	@Override
	public void setdiffB(List<Character> lb) {
		// TODO Auto-generated method stub
		diff[1].append(lb.toArray(new Character[lb.size()]));
	}
	
	public String getDiffAString() {
		return reverse?da.reverse().toString():da.toString();
	}
	
	public String getDiffBString() {
		return reverse?db.reverse().toString():db.toString();
	}
	
	@Override
	public CharacterList getDiffA() {
		CharacterList clist = new CharacterList(getDiffAString());
		return clist;
	}
	
	@Override
	public CharacterList getDiffB() {
		CharacterList clist = new CharacterList(getDiffBString());
		return clist;
	}
	
	public void setLCS(String lcs) {
		builder.append(lcs);
	}

}
