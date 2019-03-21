package burp;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Floodgate {
    final AtomicInteger remaining = new AtomicInteger(1);
    final private AtomicBoolean isOpen = new AtomicBoolean(false);

    // the python thread will set here
    void open() {
        if (isOpen.get()) {
            Utils.out("Gate is already open");
            return;
        }

        if (remaining.get() > 0) {
            new Thread(() -> {
                while (remaining.get() > 0) {
                    //Utils.out("Threads remaining: "+remaining.get());
                    synchronized (remaining) {
                        try {
                            remaining.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
                makeOpen();
            }).start();
        }
        else {
            makeOpen();
        }
    }

    private void makeOpen() {
        synchronized (isOpen) {
            isOpen.set(true);
            isOpen.notifyAll();
        }
    }

    void addWaiter() {
        remaining.incrementAndGet();
    }

    void waitForGo() throws InterruptedException {
        remaining.decrementAndGet();
        synchronized (remaining) {
            remaining.notifyAll();
        }
        synchronized (isOpen) {
            while (!isOpen.get()) {
                isOpen.wait();
            }
        }
    }

}