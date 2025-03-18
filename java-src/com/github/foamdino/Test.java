package com.github.foamdino;

/* Simple test class for connectinog agent to */
public class Test {


    String b() {
        return "return from package-private(default) b()";
    }

    private String a() {
        return "return from private method a()";
    }

    public void foo() {
        /* just perform some ops here and invoke some methods */

        for (int i=0; i<10; i++) {
            System.out.println(a());
            System.out.println(b());
        }
    }

    public static void main(String[] args) {

        Test t = new Test();
        t.foo();
    }
}
