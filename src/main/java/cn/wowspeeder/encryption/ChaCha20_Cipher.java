package cn.wowspeeder.encryption;

import com.fasterxml.jackson.core.util.ByteArrayBuilder;
import com.igormaznitsa.jbbp.JBBPParser;
import com.igormaznitsa.jbbp.model.*;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.IntStream;

public class ChaCha20_Cipher extends StreamCiper{

    static int KEY_LENGTH = 32;
    static int IV_LENGTH = 8;
    public static String CIPHER_CHACHA20 = "chacha20";
    static List<int[]> orders_chacha20 =  ChaCha20_Cipher.getORDERS_CHACHA20();
    int counter ;

    public static Map<String, String> getCiphers() {
        Map<String, String> ciphers = new HashMap<String, String>();
        ciphers.put(CIPHER_CHACHA20, ChaCha20_Cipher.class.getName());
        return ciphers;
    }

    public ChaCha20_Cipher(byte[] key) {
        this(key, false, true, 0);
    }

    public ChaCha20_Cipher(byte[] key, boolean ota, boolean setup_key) {
        this(key, ota, setup_key, 0);  // musst use this
    }

    public ChaCha20_Cipher(byte[] key, boolean ota, boolean setup_key, int counter) {
        super(key, ota, setup_key);
        this.counter = counter;
    }
    //    @Override
    public int getKeyLength() {
        return ChaCha20_Cipher.KEY_LENGTH;
    }

    public int getIVLength () {
        return ChaCha20_Cipher.IV_LENGTH;
    }

//    public static <T> List<List<T>> zip(List<T>... lists) {
//        List<List<T>> zipped = new ArrayList<List<T>>();
//        for (List<T> list : lists) {
//            for (int i = 0, listSize = list.size(); i < listSize; i++) {
//                List<T> list2;
//                if (i >= zipped.size())
//                    zipped.add(list2 = new ArrayList<T>());
//                else
//                    list2 = zipped.get(i);
//                list2.add(list.get(i));
//            }
//        }
//        return zipped;
//    }

    public int[][] zip(int[]... lists) {
        int len = lists.length;
        int ilen = lists[0].length;
        int[][] zipped = new int[ilen][len];
        for (int j=0; j< lists.length; j++) {
            for (int i = 0, listSize = lists[j].length; i < listSize; i++) {
                zipped[i][j] = lists[j][i];
            }
        }
        return zipped;
    }

    // ORDERS_CHACHA20 = ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)) * 10
    static List<int[]> getORDERS_CHACHA20(){
        List<int[]> ret = new ArrayList<>();
        for(int i: IntStream.range(0, 10).toArray()){
            ret.add(new int[]{0,4,8,12});
            ret.add(new int[]{1,5,9,13});
            ret.add(new int[]{2,6,10,14});
            ret.add(new int[]{3,7,11,15});
            ret.add(new int[]{0,5,10,15});
            ret.add(new int[]{1,6,11,12});
            ret.add(new int[]{2,7,8,13});
            ret.add(new int[]{3,4,9,14});
        }
        return ret;
    }

    public int[] ChaCha20_round(int[] H){
        for(int[] order : orders_chacha20){
            int a = order[0];
            int b = order[1];
            int c = order[2];
            int d = order[3];
            H[a] += H[b];
            H[d] = Integers.rotateLeft(H[d]^H[a], 16);
            H[c] += H[d];
            H[b] = Integers.rotateLeft(H[b]^H[c], 12);
            H[a] += H[b];
            H[d] = Integers.rotateLeft(H[d]^H[a], 8);
            H[c] += H[d];
            H[b] = Integers.rotateLeft(H[b]^H[c], 7);
        }
        return H;
    }

    public Generator<Byte> core() {
        Generator<Byte> n = new Generator<Byte>() {
            @Override
            protected void run() throws Exception {
                ByteArrayBuilder init_builder = new ByteArrayBuilder();
                init_builder.write("expand 32-byte k".getBytes());
                init_builder.write(key);
                init_builder.write(Pack.intToLittleEndian(counter));
                init_builder.write(new byte[12 - getIVLength()]);
                init_builder.write(iv);
                byte[] init_bytes = init_builder.toByteArray();
                int[] data = Pack.littleEndianToInt(init_bytes, 0, 16);

                while(true){
                    int[] tmp_builder = new int[16];
                    int i = 0;
                    for(int[] tmp: zip(ChaCha20_round(data.clone()), data)){
                        int a = tmp[0];
                        int b = tmp[1];
                        int c = a + b & 0xffffffff;
                        tmp_builder[i] = c;
                        i++;
                    }

                    byte[] yield_bytes = Pack.intToLittleEndian(tmp_builder);
                    for(byte y : yield_bytes){
                        yield(y);
                    }
                    if(data[12] == 0xffffffff){
                        data[12] = 0;
                        data[13] = data[13] + 1;
                    }else{
                        data[12] = data[12] + 1;
                        data[13] = data[13];
                    }
                }
            }
        };
        return n;
    }

    public void setup(){
//        System.out.println("StreamCipher... setup");
        super.setup();
    }


    public static void main(String[] args) throws Exception {
        ChaCha20_Cipher c = new ChaCha20_Cipher("helloworld".getBytes());
        c.setup_iv();
        ByteArrayBuilder init_builder = new ByteArrayBuilder();
//        init_builder.write("expand 32-byte k".getBytes());
//        init_builder.write(c.key);
//        init_builder.write(Pack.intToLittleEndian(c.counter));
//
//        init_builder.write(c.iv);
//        init_builder.write(new byte[12 - c.getIVLength()]);
//        byte[] init_bytes = init_builder.toByteArray();
        ByteBuffer byteBuffer = ByteBuffer.allocate(256);
        IntStream.range(0, 64).forEach(n -> byteBuffer.putInt(n));

        byte[] a = {-1, -2, -3, -3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63};
        // python !16I  is there is a 16 I for this format
        int[] data0 = JBBPParser.prepare("<int:32 [_];").parse(a).
                findFieldForType(JBBPFieldArrayInt.class).getArray();

        long x = Integer.toUnsignedLong(data0[0]);
        // byte and signed
        int[] data = Pack.littleEndianToInt(a, 0, 16);
        System.out.println();
    }
}
