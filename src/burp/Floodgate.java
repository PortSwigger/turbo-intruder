package burp;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Floodgate {
    final AtomicInteger remaining = new AtomicInteger(1);
    final private AtomicBoolean isOpen = new AtomicBoolean(false);

    // the python thread will set here
    void open() throws InterruptedException {
        while (remaining.get() > 0) {
            synchronized (remaining) {
                remaining.wait();
            }
        }
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