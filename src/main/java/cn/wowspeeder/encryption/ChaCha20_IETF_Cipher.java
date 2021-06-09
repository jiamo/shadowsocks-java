package cn.wowspeeder.encryption;

import com.fasterxml.jackson.core.util.ByteArrayBuilder;
import com.igormaznitsa.jbbp.JBBPParser;
import com.igormaznitsa.jbbp.model.*;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.IntStream;

public class ChaCha20_IETF_Cipher extends ChaCha20_Cipher{

    static int KEY_LENGTH = 32;
    static int IV_LENGTH = 12;
    public static String CIPHER_CHACHA20_IETF = "chacha20-ietf";
//    static List<int[]> orders_chacha20 =  ChaCha20_Cipher.getORDERS_CHACHA20();
    int counter ;

    public static Map<String, String> getCiphers() {
        Map<String, String> ciphers = new HashMap<String, String>();
        ciphers.put(CIPHER_CHACHA20_IETF, ChaCha20_IETF_Cipher.class.getName());
        return ciphers;
    }

    public ChaCha20_IETF_Cipher(byte[] key) {
        this(key, false, true, 0);
    }

//    public ChaCha20_Cipher(byte[] key, boolean ota, boolean setup_key) {
//        this(key, ota, setup_key, 0);  // musst use this
//    }
//
    public ChaCha20_IETF_Cipher(byte[] key, boolean ota, boolean setup_key, int counter) {
        super(key, ota, setup_key, counter);
//        this.counter = counter;
    }
    //    @Override
    public int getKeyLength() {
        return ChaCha20_IETF_Cipher.KEY_LENGTH;
    }

    public int getIVLength () {
        return ChaCha20_IETF_Cipher.IV_LENGTH;
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
