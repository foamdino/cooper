package com.github.foamdino;

/* Simple test class for connectinog agent to */
public class Test {

    int c(int foo, String bar) throws Exception {
        throw new Exception("Thrown from c");
    }

    String b() {
        return "return from package-private(default) b()";
    }

    private String a() {
        return "return from private method a()";
    }

    public void foo() throws Exception {
        /* just perform some ops here and invoke some methods */

        for (int i=0; i<10; i++) {
            System.out.println(a());
            Thread.sleep(10000);
            System.out.println(b());
        }
        c(10, "hello");
    }

    public static void main(String[] args) throws Exception {

        try {
            Test t = new Test();
            t.foo();
        } catch (Exception e) {
            e.printStackTrace();
        }
        /* wait so that exception details can be sent to log */
        Thread.sleep(20000);
    }
}
