package burp;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Floodgate {
    final AtomicInteger remaining = new AtomicInteger(1);
    final private AtomicBoolean isOpen = new AtomicBoolean(false);

    // the python thread will set here
    void open() throws InterruptedException {
        if (isOpen.get()) {
            Utils.out("Gate is already open");
            return;
        }

        while (remaining.get() > 0) {
            Utils.out("Threads remaining: "+remaining.get());
            synchronized (remaining) {
                remaining.wait();
            }
        }

        synchronized (isOpen) {
            isOpen.set(true);
            isOpen.notifyAll();
            //Utils.out("Gate opened");
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