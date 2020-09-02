package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Edit graph cell for O(NP) comparison logic
 *
 * @author gdgd009xcd
 *
 */
public class OnpV {
	public int x =0;
	
	int oper = 0;
	int snakecnt = 0;//snakecnt>0 : snake x++;y++;
	int P = -1;//current P
	List<Integer> operhist = null;
	boolean refered = false;
	//HashMap<Integer, Integer> operhist = null;//operhist[p] = oper at p
	HashMap<Integer, Integer> snakehist = null;//snakehist[p] = snakecnt at p

	
	OnpV(int _x){
		x = _x;
	}

	
	OnpV(int _x, int p, int _oper){
		operhist = new ArrayList<>();
		snakehist = new HashMap<Integer, Integer>();
		setOper(_x, p, _oper);
	}
	
	public void setOper(int _x, int p, int _oper) {
		if(p!=P&&P!=-1&&refered==true) {
			saveHist();
		}
		refered = false;
		x = _x;
		oper = _oper;
		snakecnt = 0;
		P = p;
	}
	
	public void saveHist() {

			if(oper==1) {
				operhist.add(P);
			}
			if(snakecnt>0) {
				//int hsnk = 0;
				//if((hsnk = getSnake(P))==0) {
					snakehist.put(P, snakecnt);
				//}
			}

	}
	
	public int getOperHistSize() {
		return operhist.size();
	}
	
	public int getSnakeHistSize() {
		return snakehist.size();
	}
	
	public int getOper(int p) {
		boolean  histoper = operhist.indexOf(p) != -1 ? true : false;
		if(histoper==false) {
			if(p==P) {//current P
				return oper;
			}
			return -1;
		}
		return 1;
	}
	
	public int getSnake(int p) {
		Integer histsnake = snakehist.get(p);
		if(histsnake==null) {
			if(p==P) {//current P
				return snakecnt;
			}
			return 0;
		}
		return histsnake;
	}

	
	public void addSnake(int _x) {
		x =_x;
		snakecnt++;
	}
	
	public void setSnake(int _scnt) {
			x += _scnt;
			snakecnt += _scnt;
	}
	
	public void setRefered() {
		refered = true;
	}
	

	

	

	
}