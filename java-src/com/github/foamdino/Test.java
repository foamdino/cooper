package com.github.foamdino;

/**
 * Test class for the Cooper JVM Agent
 * 
 * This class is designed to test various method call patterns that might
 * trigger the issue with method entry/exit mismatches.
 * 
 * To run with the agent:
 * java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test
 */
public class Test {

    public static void main(String[] args) {
        System.out.println("Starting Cooper JVM Agent test");
        
        // Test direct method call
        Test test = new Test();
        String result = test.a();
        System.out.println("Method a() returned: " + result);
        
        // Test nested method calls
        test.nestedMethodTest();
        
        // Test exception handling
        test.exceptionTest();
        
        // Test recursive method calls
        test.recursiveTest(3);
        
        System.out.println("Test completed");
    }

    /**
     * Simple method call - should be tracked by agent
     */
    public String a() {
        // Do some work to make the method execution take measurable time
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        return "Hello from method a";
    }
    
    /**
     * Another simple method - might be tracked depending on config
     */
    public String b() {
        // Do some work
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        return "Hello from method b";
    }
    
    /**
     * Test nested method calls to see if stack tracking works correctly
     */
    public void nestedMethodTest() {
        System.out.println("Starting nested method test");
        
        // First level
        methodLevel1();
        
        System.out.println("Nested method test completed");
    }
    
    private void methodLevel1() {
        // Do some work
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        // Call the next level
        methodLevel2();
    }
    
    private void methodLevel2() {
        // Do some work
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        // Call the next level
        methodLevel3();
    }
    
    private void methodLevel3() {
        // Do some work
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        // Allocate some memory to test memory tracking
        byte[] data = new byte[10 * 1024]; // 10KB
    }
    
    /**
     * Test exception handling to see if stack unwinding works correctly
     */
    public void exceptionTest() {
        System.out.println("Starting exception test");
        
        try {
            throwingMethod();
        } catch (RuntimeException e) {
            System.out.println("Caught exception: " + e.getMessage());
        }
        
        System.out.println("Exception test completed");
    }
    
    private void throwingMethod() {
        // Do some work before throwing
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        // Call another method that will throw
        deepThrowingMethod();
    }
    
    private void deepThrowingMethod() {
        // Do some work before throwing
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        // Create some garbage to test memory tracking during exceptions
        byte[] data = new byte[5 * 1024]; // 5KB
        
        // Throw an exception
        throw new RuntimeException("Test exception");
    }
    
    /**
     * Test recursive method calls to see if deep stacks are handled correctly
     */
    public void recursiveTest(int depth) {
        System.out.println("Recursive test: depth " + depth);
        
        // Do some work at this level
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            // Ignore
        }
        
        // Allocate memory proportional to depth
        byte[] data = new byte[depth * 1024]; // depth KB
        
        // Base case
        if (depth <= 0) {
            System.out.println("Reached base case of recursion");
            return;
        }
        
        // Recursive call
        recursiveTest(depth - 1);
        
        System.out.println("Exiting recursion level " + depth);
    }
    
    /**
     * Test parallel method calls to see if thread-local contexts work correctly
     */
    public void parallelTest() {
        System.out.println("Starting parallel test");
        
        // Create threads that call our tracked methods
        Thread t1 = new Thread(() -> {
            String result = a();
            System.out.println("Thread 1: " + result);
        });
        
        Thread t2 = new Thread(() -> {
            String result = b();
            System.out.println("Thread 2: " + result);
        });
        
        // Start threads
        t1.start();
        t2.start();
        
        // Wait for threads to complete
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            System.out.println("Thread interrupted");
        }
        
        System.out.println("Parallel test completed");
    }
}