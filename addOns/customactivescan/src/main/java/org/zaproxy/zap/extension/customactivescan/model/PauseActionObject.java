package org.zaproxy.zap.extension.customactivescan.model;

import org.zaproxy.zap.extension.customactivescan.ExtensionAscanRules;

public class PauseActionObject {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private int pauseCounter = 0;
    private boolean isTerminated = false;

    synchronized void onceWaiter() {
        try {
            while (!isTerminated) {
                LOGGER4J.debug("start wait");
                wait();
                LOGGER4J.debug("end wait");
            }
        }catch(InterruptedException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
    }

    public boolean createNewThread(int scannerId) {
        boolean isCreatedNewThread = false;
        Thread currentTh = ExtensionAscanRules.scannerIdThreadMap.get(scannerId);
        if (currentTh == null) {
            this.awake();
            final PauseActionObject thisPauseActionObject = this;
            Thread pauseActionThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    thisPauseActionObject.onceWaiter();
                }
            });

            pauseActionThread.start();
            boolean isWaitingState = false;
            String stateString = null;
            LOGGER4J.debug("enter case waitingState [" + getState(pauseActionThread) + "]");
            while(!isWaitingState) {
                stateString = null;
                switch(pauseActionThread.getState()) {
                    case WAITING:
                        stateString = "WAITING";
                        isWaitingState = true;
                        break;
                    case TIMED_WAITING:
                        stateString = "TIMED_WAITING";
                        isWaitingState = true;
                        break;
                    case TERMINATED:
                        stateString = "TERMINATED";
                        isWaitingState = true;
                        break;
                    default:
                        break;
                }
                if (stateString != null) {
                    LOGGER4J.debug("new thread state[" + stateString + "]");
                }
            }
            LOGGER4J.debug("thread id[" + pauseActionThread.getId() + "] started");
            if (pauseActionThread.isAlive() && pauseActionThread.getState() == Thread.State.WAITING ) {
                isCreatedNewThread = true;
                ExtensionAscanRules.scannerIdThreadMap.put(scannerId, pauseActionThread);
            } else {// kill 'em all
                thisPauseActionObject.terminate();
                thisPauseActionObject.notifyAll();
                isCreatedNewThread = false;
            }
        }
        return isCreatedNewThread;
    }

    synchronized public void terminateWaitingThread() {
        terminate();
        notify();
    }

    public void terminate() {
        isTerminated = true;
        LOGGER4J.debug("PauseActionObject terminated.");
    }

    private void awake() {
        isTerminated = false;
    }

    public boolean isTerminated() {
        return isTerminated;
    }

    public void setCounter(int pauseCounter) {
        this.pauseCounter = pauseCounter;
    }

    public boolean isCounterDecrementable() {
        return this.pauseCounter >= 0 ? true: false;
    }

    public int decrementCounter() {
        LOGGER4J.debug("dec " + this.pauseCounter + "->" + (this.pauseCounter-1));
        return this.pauseCounter--;
    }

    private String getState(Thread th) {
        String stateString = "";
        if (th != null) {
            switch(th.getState()) {
                case NEW:
                    stateString = "NEW";
                    break;
                case BLOCKED:
                    stateString = "BLOCKED";
                    break;
                case WAITING:
                    stateString = "WAITING";
                    break;
                case RUNNABLE:
                    stateString = "RUNNABLE";
                    break;
                case TERMINATED:
                    stateString = "TERMINATED";
                    break;
                case TIMED_WAITING:
                    stateString = "TIMED_WAITING";
                    break;
                default:
                    break;
            }
        }
        return stateString;
    }
}
