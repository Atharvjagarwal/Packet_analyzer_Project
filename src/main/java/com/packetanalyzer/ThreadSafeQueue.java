package com.packetanalyzer;

import java.util.ArrayDeque;
import java.util.Queue;

public final class ThreadSafeQueue<T> {
    private final Queue<T> queue = new ArrayDeque<>();
    private final int capacity;
    private boolean closed;

    public ThreadSafeQueue(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("Queue capacity must be positive");
        }
        this.capacity = capacity;
    }

    public synchronized void put(T item) throws InterruptedException {
        while (queue.size() >= capacity && !closed) {
            wait();
        }
        if (closed) {
            throw new IllegalStateException("Cannot enqueue into a closed queue");
        }
        queue.add(item);
        notifyAll();
    }

    public synchronized T take() throws InterruptedException {
        while (queue.isEmpty() && !closed) {
            wait();
        }
        T item = queue.poll();
        notifyAll();
        return item;
    }

    public synchronized void close() {
        closed = true;
        notifyAll();
    }

    public synchronized boolean isClosed() {
        return closed;
    }
}
