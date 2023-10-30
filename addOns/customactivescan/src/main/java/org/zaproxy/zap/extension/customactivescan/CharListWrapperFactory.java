package org.zaproxy.zap.extension.customactivescan;

import java.util.ArrayList;
import java.util.List;

public class CharListWrapperFactory {
    String string;
    CharListWrapperFactory(String string){
        this.string = string;
    }

    ArrayListWrapper<Character> getCharListWrapper() {
        return  new ArrayListWrapper<>() {
            final String stringA = CharListWrapperFactory.this.string;
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

    }

    ArrayListWrapper<String> getStringListWrapper() {
        return  new ArrayListWrapper<>() {
            final String stringA = CharListWrapperFactory.this.string;
            @Override
            public int size() {
                return stringA.length();
            }

            @Override
            public String get(int index) {
                return String.valueOf(stringA.charAt(index));
            }

            @Override
            public boolean isOriginalReverseOrder() {
                return false;
            }

            @Override
            public List<String> getOriginalList() {
                char[] charArray = stringA.toCharArray();
                List<String> clist = new ArrayList<>();
                for(char c: charArray) {
                    clist.add(String.valueOf(c));
                }
                return clist;
            }

            @Override
            public int getRowSize() {
                return 1;
            }

            @Override
            public String getDelimiter() {
                return null;
            }
        };

    }
}
