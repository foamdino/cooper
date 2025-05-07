package com.github.foamdino;

/* Just a test class that we can instantiate to trigger object allocation events */
class Junk {

    private String name;
    private Long id;

    public Junk(String name, Long id) {
        this.name = name;
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}

/* Simple test class for connecting agent to */
public class Test {

    int c(int foo, String bar) throws Exception {
        throw new Exception("Thrown from c");
    }

    String b() {
        return "return from package-private(default) b()";
    }

    private String a() {
        var message = new String();
        message += "return ";
        message += "from ";
        message += "private ";
        message += "method ";
        message += " a()";

        var j = new Junk("Test", new Long(1));
        var j2 = new Junk("Another test", new Long(2));
        j2.setId(new Long(10));
        j2.setName("Changed name");

        return message;
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
