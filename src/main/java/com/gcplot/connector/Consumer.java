package com.gcplot.connector;

public interface Consumer<T> {
    void consume(T t);
}
