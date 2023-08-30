package org.zaproxy.zap.extension.customactivescan;

import java.util.List;

public class ArrayListWrapperFactory {
    private List<String> list = null;
    private int listRowSize;
    private String listDelimiter;
    private LcsStringList lcsStringList = null;
    private boolean isReverseListOrder;

    public ArrayListWrapperFactory(List<String> list, boolean isReverseListOrder, int rowSize, String delimiter) {
        this.list = list;
        this.isReverseListOrder = isReverseListOrder;
        this.listRowSize = rowSize;
        this.listDelimiter = delimiter;
    }

    public ArrayListWrapperFactory(LcsStringList lcsStringList) {
        this.lcsStringList = lcsStringList;
        this.isReverseListOrder = lcsStringList.isReverseLCS();
    }

    public  enum ListType {
      LCS,
      DIFFA,
      DIFFB,
      LIST
    };

    public ArrayListWrapper<String> createArrayListWrapper() {
        return createArrayListWrapper(ListType.LIST);
    }

    public ArrayListWrapper<String> createArrayListWrapper(ListType type) {
        if (this.list != null) {
            if (this.isReverseListOrder) {
                return new ArrayListWrapper<String>() {
                    private List<String> list = ArrayListWrapperFactory.this.list;
                    final private int size = list.size();
                    final private int sizeOffset = size - 1;
                    final int rowSize = ArrayListWrapperFactory.this.listRowSize;
                    final String delimiter = ArrayListWrapperFactory.this.listDelimiter;

                    @Override
                    public int size() {
                        return size;
                    }

                    @Override
                    public String get(int index) {
                        int xedni = sizeOffset - index;
                        return list.get(xedni);
                    }

                    @Override
                    public boolean isOriginalReverseOrder() {
                        return true;
                    }

                    @Override
                    public List<String> getOriginalList() {
                        return list;
                    }

                    @Override
                    public int getRowSize() {
                        return rowSize;
                    }

                    @Override
                    public String getDelimiter() {
                        return delimiter;
                    }
                };
            } else {
                return new ArrayListWrapper<String>() {
                    private List<String> list = ArrayListWrapperFactory.this.list;
                    final int rowSize = ArrayListWrapperFactory.this.listRowSize;
                    final String delimiter = ArrayListWrapperFactory.this.listDelimiter;

                    @Override
                    public int size() {
                        return list.size();
                    }

                    @Override
                    public String get(int index) {
                        return list.get(index);
                    }

                    @Override
                    public boolean isOriginalReverseOrder() {
                        return false;
                    }

                    @Override
                    public List<String> getOriginalList() {
                        return list;
                    }

                    @Override
                    public int getRowSize() {
                        return rowSize;
                    }

                    @Override
                    public String getDelimiter() {
                        return delimiter;
                    }
                };
            }
        } else if (this.lcsStringList != null) {
            ArrayListWrapper<String> actionCreated = null;
            switch(type) {
                case LCS:
                    if (this.lcsStringList.isReverseLCS()){
                        actionCreated =  new ArrayListWrapper<String>() {
                            private LcsStringList lcsStringList = ArrayListWrapperFactory.this.lcsStringList;
                            final private int size = lcsStringList.size();
                            final private int sizeOffset = size - 1;
                            final int rowSize = lcsStringList.getRowSize();
                            final String delimiter = lcsStringList.getDelimiter();

                            @Override
                            public int size() {
                                return size;
                            }

                            /**
                             * get LCS element at index position<br>
                             * this method return in original order.
                             * @param index
                             * @return
                             */
                            @Override
                            public String get(int index) {
                                int xedni = sizeOffset - index;
                                return lcsStringList.getLcsElement(xedni);
                            }

                            @Override
                            public boolean isOriginalReverseOrder() {
                                return true;
                            }

                            @Override
                            public List<String> getOriginalList() {
                                return lcsStringList.getOriginalLcs();
                            }

                            @Override
                            public int getRowSize() {
                                return rowSize;
                            }

                            @Override
                            public String getDelimiter() {
                                return delimiter;
                            }
                        };
                    } else {
                        actionCreated =  new ArrayListWrapper<String>() {
                            private LcsStringList lcsStringList = ArrayListWrapperFactory.this.lcsStringList;
                            private int size = lcsStringList.size();
                            final int rowSize = lcsStringList.getRowSize();
                            final String delimiter = lcsStringList.getDelimiter();

                            @Override
                            public int size() {
                                return size;
                            }

                            /**
                             * get LCS element at index position.
                             * this method return in original order.
                             * @param index
                             * @return
                             */
                            @Override
                            public String get(int index) {
                                return lcsStringList.getLcsElement(index);
                            }

                            @Override
                            public boolean isOriginalReverseOrder() {
                                return false;
                            }

                            @Override
                            public List<String> getOriginalList() {
                                return lcsStringList.getOriginalLcs();
                            }

                            @Override
                            public int getRowSize() {
                                return rowSize;
                            }

                            @Override
                            public String getDelimiter() {
                                return delimiter;
                            }
                        };
                    }
                    break;
                case DIFFA:
                    if (this.lcsStringList.isReverseDiffA()){
                        actionCreated = new ArrayListWrapper<String>() {
                            private LcsStringList lcsStringList = ArrayListWrapperFactory.this.lcsStringList;
                            final private int size = lcsStringList.getDiffASize();
                            final private int sizeOffset = size - 1;
                            final int rowSize = lcsStringList.getRowSize();
                            final String delimiter = lcsStringList.getDelimiter();

                            @Override
                            public int size() {
                                return size;
                            }

                            @Override
                            public String get(int index) {
                                int xedni = sizeOffset - index;
                                return lcsStringList.getDiffAElement(xedni);
                            }

                            @Override
                            public boolean isOriginalReverseOrder() {
                                return true;
                            }

                            @Override
                            public List<String> getOriginalList() {
                                return lcsStringList.getOriginalDiffA();
                            }

                            @Override
                            public int getRowSize() {
                                return rowSize;
                            }

                            @Override
                            public String getDelimiter() {
                                return delimiter;
                            }
                        };
                    } else {
                        actionCreated = new ArrayListWrapper<String>() {
                            private LcsStringList lcsStringList = ArrayListWrapperFactory.this.lcsStringList;
                            private int size = lcsStringList.getDiffASize();
                            final int rowSize = lcsStringList.getRowSize();
                            final String delimiter = lcsStringList.getDelimiter();

                            @Override
                            public int size() {
                                return size;
                            }

                            @Override
                            public String get(int index) {
                                return lcsStringList.getDiffAElement(index);
                            }

                            @Override
                            public boolean isOriginalReverseOrder() {
                                return false;
                            }

                            @Override
                            public List<String> getOriginalList() {
                                return lcsStringList.getOriginalDiffA();
                            }

                            @Override
                            public int getRowSize() {
                                return rowSize;
                            }

                            @Override
                            public String getDelimiter() {
                                return delimiter;
                            }
                        };
                    }
                    break;
                case DIFFB:
                    if (this.lcsStringList.isReverseDiffB()) {
                        actionCreated = new ArrayListWrapper<String>() {
                            private LcsStringList lcsStringList = ArrayListWrapperFactory.this.lcsStringList;
                            final private int size = lcsStringList.getDiffBSize();
                            final private int sizeOffset = size - 1;
                            final int rowSize = lcsStringList.getRowSize();
                            final String delimiter = lcsStringList.getDelimiter();

                            @Override
                            public int size() {
                                return size;
                            }

                            @Override
                            public String get(int index) {
                                int xedni = sizeOffset - index;
                                return lcsStringList.getDiffBElement(xedni);
                            }

                            @Override
                            public boolean isOriginalReverseOrder() {
                                return true;
                            }

                            @Override
                            public List<String> getOriginalList() {
                                return lcsStringList.getOriginalDiffB();
                            }

                            @Override
                            public int getRowSize() {
                                return rowSize;
                            }

                            @Override
                            public String getDelimiter() {
                                return delimiter;
                            }
                        };
                    } else {
                        actionCreated = new ArrayListWrapper<String>() {
                            private LcsStringList lcsStringList = ArrayListWrapperFactory.this.lcsStringList;
                            private int size = lcsStringList.getDiffBSize();
                            final int rowSize = lcsStringList.getRowSize();
                            final String delimiter = lcsStringList.getDelimiter();

                            @Override
                            public int size() {
                                return size;
                            }

                            @Override
                            public String get(int index) {
                                return lcsStringList.getDiffBElement(index);
                            }

                            @Override
                            public boolean isOriginalReverseOrder() {
                                return false;
                            }

                            @Override
                            public List<String> getOriginalList() {
                                return lcsStringList.getOriginalDiffB();
                            }

                            @Override
                            public int getRowSize() {
                                return rowSize;
                            }

                            @Override
                            public String getDelimiter() {
                                return delimiter;
                            }
                        };
                    }
                    break;
            }
            return actionCreated;
        }
        return null;
    }
}
