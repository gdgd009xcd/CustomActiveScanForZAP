package org.zaproxy.zap.extension.customactivescan;

import org.apache.logging.log4j.Logger;

import java.util.List;

public abstract class AbstractLcsComparator<T> implements LcsComparator<T>{
	protected  Logger log = null;
	AbstractLcsComparator(Logger _log){
		log = _log;
	}
	
	protected Logger getLogger() {
		return log;
	}
	
	@Override
	public int calcPercent(ArrayListWrapper<T> a, ArrayListWrapper<T> b, LcsBuilder<T> result){

		int asize = -1;
		int bsize = -1;

		asize = a.size();
		bsize = b.size();

		if(asize==0 && bsize == 0){

			if(log!=null){
				log.debug("calcPercent=" + 100);
			}
			return 1000;//サイズ０
		}else{
			int lcs = calcLCS(a, b, result);
			if(lcs>0){
				int mlen = asize;
				int pintA = getPercentage(lcs, asize);
				int pintB = getPercentage(lcs, bsize);
				int pint = pintA;
				if(asize < bsize){
					pint = pintB;
				}
				result.setPercents(pintA, pintB);
				if(log!=null){
					log.debug("calcPercent=" + pint);
				}
				return pint;
			}
		}
		if(log!=null){
			log.debug("calcPercent=" + 0);
		}
		return 0;
	}

	private int getPercentage(int lcs, int mlen) {
		double percent = (double) lcs/mlen * 1000;
		int pint = (int) Math.round(percent);
		if(lcs!=mlen&& pint == 1000) pint = 999;
		return pint;
	}
}
