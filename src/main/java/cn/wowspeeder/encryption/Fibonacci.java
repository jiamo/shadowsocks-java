package cn.wowspeeder.encryption;

public class Fibonacci extends Generator<Integer> {


    /**
     * Override the default constructor to set the timeout parameters.
     */
    public Fibonacci() {
        super(1,5);
    }

    @Override
    protected void run() throws Exception {
        yield(0);
        int i = 0;
        int j = 1;
        while (true) {
            yield(j);
            int current = i + j;
            i = j;
            j = current;
            if(j > 10){
                break;
            }
        }
    }

    public static void main(final String[] args) {
        // Use get method to get the values yielded by the generator.
        Fibonacci fibonacci = new Fibonacci();
        for (int i = 0; i < 50; i++) {
            System.out.println(fibonacci.get());
        }
        fibonacci.stop();

    }
}