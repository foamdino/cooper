package com.github.foamdino;

/* Simple test class for connectinog agent to */
public class Test {


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
    }

    public static void main(String[] args) throws Exception {

        Test t = new Test();
        t.foo();
    }
}
