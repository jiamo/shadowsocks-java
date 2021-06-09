package cn.wowspeeder.encryption;

import com.fasterxml.jackson.core.util.ByteArrayBuilder;
import com.fasterxml.jackson.databind.node.BigIntegerNode;
import com.google.common.primitives.Bytes;
import com.igormaznitsa.jbbp.mapper.Bin;
import com.sun.tools.internal.xjc.reader.dtd.bindinfo.BindInfo;
import io.vavr.Function3;
//import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;


import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

public class ChaCha20_IETF_POLY1305_Cipher extends AEADCipher{

    static int KEY_LENGTH = 32;
    static int IV_LENGTH = 32;
    static int Nonce_LENGTH = 12;
    static int Tag_LENGTH = 16;


    public static String CIPHER_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305";
    //    static List<int[]> orders_chacha20 =  ChaCha20_Cipher.getORDERS_CHACHA20();
    int counter ;

    //    @Override
    public int getKeyLength () {
        return ChaCha20_IETF_POLY1305_Cipher.KEY_LENGTH;
    }

    public int getIVLength () {
        return ChaCha20_IETF_POLY1305_Cipher.IV_LENGTH;

    }

    public int getNonceLength () {
        return ChaCha20_IETF_POLY1305_Cipher.Nonce_LENGTH;
    }

    public int getTag_LENGTH () {
        return ChaCha20_IETF_POLY1305_Cipher.Tag_LENGTH;
    }


    public static Map<String, String> getCiphers() {
        Map<String, String> ciphers = new HashMap<String, String>();
        ciphers.put(CIPHER_CHACHA20_IETF_POLY1305, ChaCha20_IETF_POLY1305_Cipher.class.getName());
        return ciphers;
    }

    Function3<byte[], byte[], Integer, byte[]> cipher_encrypt;
    public ChaCha20_IETF_POLY1305_Cipher(byte[] key) {
        this(key, false, true);
    }

    public ChaCha20_IETF_POLY1305_Cipher(byte[] key, boolean ota, boolean setup_key) {
        super(key, ota, setup_key);
    }

    public static byte[] toByteArrayLittleEndianUnsigned(BigInteger bi) {
        byte[] extractedBytes = toByteArrayUnsigned(bi);
        byte[] reversed = bigToLittle(extractedBytes);
        return reversed;
    }

    public static byte[] toByteArrayUnsigned(BigInteger bi) {
        byte[] extractedBytes = bi.toByteArray();
        int skipped = 0;
        boolean skip = true;
        for (byte b : extractedBytes) {
            boolean signByte = b == (byte) 0x00;
            if (skip && signByte) {
                skipped++;
                continue;
            } else if (skip) {
                skip = false;
            }
        }
        extractedBytes = Arrays.copyOfRange(extractedBytes, skipped,
                extractedBytes.length);
        return extractedBytes;
    }

    private int intLength(BigInteger b) {
        return (b.bitLength() >>> 5) + 1;
    }

//    public BigInteger and(BigInteger val1, BigInteger val2) {
//        int[] result = new int[Math.max(intLength(val1), intLength(val2))];
//        for (int i=0; i < result.length; i++)
//            result[i] = (val1.getInt(result.length-i-1)
//                    & val2.getInt(result.length-i-1));
//
//        return valueOf(result);
//    }


    int pythonMode(int i, int i_max) {
        return ((i % i_max) + i_max) % i_max;
    }

    public byte[] poly1305(byte[] nonce, byte[] ciphertext){
        byte[] otk = cipher_encrypt.apply(nonce, new byte[32], 0);
        ByteArrayBuilder tmp = new ByteArrayBuilder();
        tmp.write(ciphertext);
        int m = pythonMode(-ciphertext.length, 16);
        tmp.write(new byte[m + 8]);
        tmp.write(intToLittleEndian(ciphertext.length, 8));
        byte[] mac_data = tmp.toByteArray();
        BigInteger acc = new BigInteger(new byte[1]);
        byte[] otk_f16 = Arrays.copyOfRange(otk, 0, 16);
        byte[] otk_b16 = Arrays.copyOfRange(otk, 16, otk.length);
        byte[] fix = new byte[]{15, -1, -1, -4, 15, -1, -1, -4, 15, -1, -1, -4, 15, -1, -1, -1};

        BigInteger r = bytesToLittleBigint(otk_f16).and(new BigInteger(fix));
        BigInteger s = bytesToLittleBigint(otk_b16);
        for(int i = 0; i < mac_data.length; i += 16){
            byte[] tmp1 = Arrays.copyOfRange(mac_data, i , i + 16);
            BigInteger mac_int = bytesToLittleBigint(Bytes.concat(tmp1, new byte[]{1}));
            // 1<<130 - 5
            BigInteger tmp2 = BigInteger.valueOf(1).shiftLeft(130).subtract(BigInteger.valueOf(5));
            acc = (r.multiply(acc.add(mac_int))).mod(tmp2);
        }
        // (1 << 128) - 1
        BigInteger tmp3 =  BigInteger.valueOf(1).shiftLeft(128).subtract(BigInteger.valueOf(1));
        BigInteger tmp5 = acc.add(s);
        BigInteger tmp4 = (acc.add(s).and(tmp3));
        byte[] big_ret = tmp4.toByteArray();
        byte[] big_left = bigToLittle(big_ret);
        return Arrays.copyOfRange(big_left, 0, getTag_LENGTH());

    }

    void setup(){

        cipher_encrypt = (nonce, s, count) -> {
            ChaCha20_IETF_Cipher cipher = new ChaCha20_IETF_Cipher(key, false, false, count);
            cipher.setup_iv(nonce);
            return cipher.encrypt(s);
        };
    }


    public byte[] encrypt_and_digest(byte[] s, byte[] tag){
        byte[] nonce = get_nonce();
        assert tag != null;
        byte[] check_tag = poly1305(nonce, s);
        for(int i=0; i < tag.length; i++){
            assert tag[i] == check_tag[i];
            if (tag[i] != check_tag[i]){
                System.out.println("tag != check_tag");
                System.exit(-1);
            }
        }
        return cipher_encrypt.apply(nonce, s, 1);
    }

    public List<byte[]> encrypt_and_digest(byte[] s){
        // this
        byte[] nonce = get_nonce();
        byte[] data = cipher_encrypt.apply(nonce, s, 1);
        return Arrays.asList(data, poly1305(nonce, data));
    }

    public byte[] decrypt_and_verify(byte[] s, byte[] tag){
        return encrypt_and_digest(s, tag);
    }

    public List<byte[]> decrypt_and_verify(byte[] s){
        return encrypt_and_digest(s);
    }

    static public byte[] bigToLittle(byte[] bytes){
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - i - 1];
            bytes[bytes.length - i - 1] = temp;
        }
        return bytes;
    }

    static public BigInteger bytesToLittleBigint(byte[] bytes){
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - i - 1];
            bytes[bytes.length - i - 1] = temp;
        }
        return new BigInteger(1, bytes);
    }

    static byte[] toByte(int[] data) {

        byte[] bytes = new byte[data.length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) data[i];
        }
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        int[] a = IntStream.range(16, 32).toArray();
        // acc, r, s = 0, int.from_bytes(otk[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff, int.from_bytes(otk[16:], 'little')

        byte[] b = new byte[]{15, -1, -1, -4, 15, -1, -1, -4, 15, -1, -1, -4, 15, -1, -1, -1};
        byte[] bytes = toByte(a);

        BigInteger c = bytesToLittleBigint(bytes);;
        System.out.println(c);
        BigInteger c2 = new BigInteger(b);
        // xx
        c = c.and(c2);
        System.out.println(c);
        System.out.println();

//        System.out.println(transform(b));
    }
}
