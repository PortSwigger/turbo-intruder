package burp;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Floodgate {
    final AtomicInteger remaining = new AtomicInteger(1);
    final AtomicBoolean isOpen = new AtomicBoolean(false);
    final AtomicBoolean fullyQueued = new AtomicBoolean(false);
    String name;
    RequestEngine engine;

    public Floodgate(String name, RequestEngine engine) {
        this.name = name;
        this.engine = engine;
    }

    // the python thread will set here
    void open() {
        if (isOpen.get()) {
            Utils.out("Gate is already open");
            return;
        }
        fullyQueued.set(true);

        if (remaining.get() > 0) {
            //new Thread(() -> {
                while (remaining.get() > 0 && engine.getAttackState().get() < 3) {
                    //Utils.out("Threads remaining: "+remaining.get());
                    synchronized (remaining) {
                        try {
                            remaining.wait(100);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
                makeOpen();
            //}).start();
        }
        else {
            makeOpen();
        }
    }

    private void makeOpen() {
        synchronized (isOpen) {
            //Utils.out("Opened gate "+name);
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

    boolean reportReadyWithoutWaiting() {
        remaining.decrementAndGet();
        synchronized (remaining) {
            remaining.notifyAll();
        }
        return remaining.get() == 0 && fullyQueued.get();
    }

}