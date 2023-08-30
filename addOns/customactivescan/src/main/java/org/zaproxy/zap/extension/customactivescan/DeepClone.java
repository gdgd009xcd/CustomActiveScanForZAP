package org.zaproxy.zap.extension.customactivescan;

/** @author gdgd009xcd */
public interface DeepClone extends Cloneable {
    //
    //
    // Correct example:
    //
    //    class crazyobject implements DeepClone{
    //
    //    ...
    //        {@literal @}Override
    //        public crazyobject clone() { // return this Type object
    //                                    //which is not java.lang.ObjectType.
    //               crazyobject nobj =  (crazyobject) super.clone();
    //               // !! you must always use super.clone().
    //               // also inherit class must use super.clone.
    //               // DO NOT USE new XX constructor in clone().
    //               // if you use constructor then
    //               // you will get java.lang.ClassCastException attack.
    //               nobj.optlist = ListDeepCopy.listDeepCopy(this.optlist);// member of this class
    //               return nobj;
    //        }
    //
    public Object clone();
}
