package cn.wowspeeder.encryption;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Base64;

import com.amazonaws.util.IOUtils;
import com.fasterxml.jackson.core.util.ByteArrayBuilder;
import com.google.common.primitives.Ints;
import com.sun.xml.internal.xsom.impl.scd.Axis;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.Pack;

import static com.google.common.base.Preconditions.checkArgument;
//import org.bouncycastle.jcajce.provider.digest.SHA1;

public class AEADCipher extends BaseCipher{
    static int KEY_LENGTH = 16;
    static int Nonce_LENGTH = 0;
    static int Tag_LENGTH = 0;
    static int IV_LENGTH = 0;
    static String info = "ss-subkey";
    static Class CIPHER = RawCipher.class;
    static int PACKET_LIMIT = 16*1024-1;

    int _nonce;

    static int getPacketLimit(){
        return AEADCipher.PACKET_LIMIT;
    }

    Short _declen;
    ByteArrayBuilder _buffer;

    public AEADCipher(byte[] key) {
        super(key);
    }

    //    @Override
    public int getKeyLength () {
        return AEADCipher.KEY_LENGTH;
    }

    public int getIVLength () {
        return AEADCipher.IV_LENGTH;

    }

    public int getNonceLength () {
        return AEADCipher.Nonce_LENGTH;
    }

    public int getTag_LENGTH () {
        return AEADCipher.Tag_LENGTH;
    }

    public Class getCIPHER(){
        return AEADCipher.CIPHER;
    }

    public AEADCipher(byte[] key, boolean ota, boolean setup_key) {
        super(key, ota, setup_key);

    }

    private byte[] genSubkey(byte[] salt){

        try{
            Mac sha512Hmac = Mac.getInstance("HmacSHA1");
            SecretKeySpec keySpec = new SecretKeySpec(iv, "HmacSHA1");
            sha512Hmac.init(keySpec);
            byte[] randkey = sha512Hmac.doFinal(key);
            int blocks_needed = (getKeyLength() + randkey.length - 1) / randkey.length ;// len(randkey)
            byte[] output_block = new byte[0];
            ByteArrayBuilder okm = new ByteArrayBuilder();
            for(int count=0; count < blocks_needed; count +=1){
                Mac mac = Mac.getInstance("HmacSHA1");
                ByteArrayBuilder bytearray = new ByteArrayBuilder();
                bytearray.write(output_block);
                bytearray.write("ss-subkey".getBytes());
                bytearray.write(new byte[]{(byte)(count + 1)});
                SecretKeySpec spec = new SecretKeySpec(randkey, "HmacSHA1");
                mac.init(spec);
                output_block = mac.doFinal(bytearray.toByteArray());
                okm.write(output_block);
                bytearray.release();
            }

            byte[] result = okm.toByteArray();
            okm.release();
            return Arrays.copyOfRange(result, 0, getKeyLength());

        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    Object setup_iv(byte[] iv){
        if(iv == null){
            this.iv = BaseCipher.randomBytes(getIVLength());
        }
        else{
            this.iv = iv;
        }
        this.key = genSubkey(null);
        this._nonce = 0;
        this._buffer = new ByteArrayBuilder();
        this._declen = null;   // null will be object type . We should not exist primitype anymore
        setup();
        return this;
    }

    static int getBufferLength(ByteArrayBuilder b){
        byte[] tmp;
        ///
        return 0; // seem it is hard to simple get total

    }

    private static byte[] intToLittleEndian(long numero) {
        byte[] b = new byte[4];
        b[0] = (byte) (numero & 0xFF);
        b[1] = (byte) ((numero >> 8) & 0xFF);
        b[2] = (byte) ((numero >> 16) & 0xFF);
        b[3] = (byte) ((numero >> 24) & 0xFF);
        return b;
    }

    private static byte[] intToBigEndian(long numero) {
        byte[] b = new byte[4];
        b[3] = (byte) (numero & 0xFF);
        b[2] = (byte) ((numero >> 8) & 0xFF);
        b[1] = (byte) ((numero >> 16) & 0xFF);
        b[0] = (byte) ((numero >> 24) & 0xFF);
        return b;
    }

    private static byte[] intToBigEndian2(long numero) {
        byte[] b = new byte[2];
        b[1] = (byte) (numero & 0xFF);
        b[0] = (byte) ((numero >> 8) & 0xFF);
        return b;
    }

    public static int fromByteArray(byte[] bytes) {
        return fromBytes(bytes[0], bytes[1], bytes[2], bytes[3]);
    }

    public static int fromLittleByteArray(byte[] bytes) {
        return fromLittleBytes(bytes[0], bytes[1], bytes[2], bytes[3]);
    }

    public static int fromBytes(byte b1, byte b2, byte b3, byte b4) {
        return b1 << 24 | (b2 & 0xFF) << 16 | (b3 & 0xFF) << 8 | (b4 & 0xFF);
    }

    public static int fromLittleBytes(byte b1, byte b2, byte b3, byte b4) {
        return b4 << 24 | (b3 & 0xFF) << 16 | (b2 & 0xFF) << 8 | (b1 & 0xFF);
    }

    public static byte[] intToLittleEndian(int n, int length)
    {
        byte[] bs = new byte[length];
        int off =0;
        bs[off] = (byte)(n);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
        return bs;
    }

    public byte[] get_nonce(){
        byte[] ret = intToLittleEndian(_nonce, getNonceLength());
//        byte[] ret = Pack.intToLittleEndian(getNonceLength());
        _nonce = (_nonce + 1) & (( 1 << getNonceLength()) - 1);
        return ret;
    }

    public byte[] decrypt(byte[] s){
        // slice from index 5 to index 9
        // byte[] slice = Arrays.copyOfRange(myArray, 5, 10);
        // how byte delete

        // the repeat.....
        byte[] temp;
        if (iv == null) {
            setup_iv(Arrays.copyOfRange(s, 0, getIVLength()));
            temp = Arrays.copyOfRange(s, getIVLength(), s.length);
        }else{
            temp = s;
        }

        ByteArrayBuilder ret = new ByteArrayBuilder();
        _buffer.write(temp);


        byte[] op_buffer = _buffer.toByteArray();
        try{
            while(true){
                if(_declen == null){
                    if(op_buffer.length < 2 + getTag_LENGTH()){
                        break;
                    }
                    _declen = Pack.bigEndianToShort(
                            decrypt_and_verify(
                                    Arrays.copyOfRange(op_buffer, 0, 2),
                                    Arrays.copyOfRange(op_buffer, 2, 2 + getTag_LENGTH())),
                    0);
                    op_buffer = Arrays.copyOfRange(op_buffer, 2 + getTag_LENGTH(), op_buffer.length);
                }
                else{
                    if(op_buffer.length < _declen + getTag_LENGTH()){
                        break;
                    }
                    ret.write(decrypt_and_verify(
                            Arrays.copyOfRange(op_buffer, 0, _declen),
                            Arrays.copyOfRange(op_buffer, _declen, _declen + getTag_LENGTH())));
                    op_buffer = Arrays.copyOfRange(op_buffer, _declen + getTag_LENGTH(), op_buffer.length);
                    _declen = null;
                }
            }

        } catch (Exception e){
            e.printStackTrace();
            return new byte[]{0};
        }
        _buffer.release();
        _buffer.write(op_buffer);  // rebuild the buffer
        byte[] ret_bytes = ret.toByteArray();
        return ret_bytes;
    }

    public byte[] encrypt(byte[] s){
        ByteArrayBuilder ret = new ByteArrayBuilder();
        if (iv == null) {
            setup_iv();
            if(getIVLength() > 0){
                ret.write(iv);
            }
        }

        for(int i=0; i<s.length; i += getPacketLimit() ){  // PACKET_LIMIT don't in child PACKET_LIMIT

            byte[] buf = Arrays.copyOfRange(s, i, i + getPacketLimit());
            List<byte[]> len_ret = encrypt_and_digest(intToBigEndian2(buf.length));
            byte[] len_chunk = len_ret.get(0);
            byte[] len_tag = len_ret.get(1);
            List<byte[]> body_ret = encrypt_and_digest(buf);
            byte[] body_chunk = body_ret.get(0);
            byte[] body_tag = body_ret.get(1);
            ret.write(len_chunk);
            ret.write(len_tag);
            ret.write(body_chunk);
            ret.write(body_tag);

        }
        return ret.toByteArray();
    }

    public byte[] decrypt_and_verify(byte[] buffer, byte[] tag){
        return buffer;
    }
    public List<byte[]> decrypt_and_verify(byte[] buffer){
        ArrayList<byte[]> a = new ArrayList<>();
        a.add(buffer);
        a.add(buffer);
        return a;
    }
    public List<byte[]> encrypt_and_digest(byte[] buffer){
        return Arrays.asList(buffer, null);
    }
    public byte[] encrypt_and_digest(byte[] buffer, byte[] tag){
        return buffer;
    }

    public static void main(String[] args) throws Exception {

//        AEADCipher cipher = new AEADCipher("key");
//        System.out.println(cipher.setup_iv("hello".getBytes()));
//        System.out.println(KEY_LENGTH);
//        HKDFBytesGenerator tmp= new HKDFBytesGenerator(new SHA1Digest());
//        tmp.init(new HKDFParameters("s".getBytes(), "s".getBytes(), null));
//        byte[] randkey = new byte[20];
//        tmp.generateBytes(randkey, 0, 20);
//        System.out.println(randkey);
//        Mac sha512Hmac = Mac.getInstance("HmacSHA1");
//        SecretKeySpec keySpec = new SecretKeySpec(
//                "s".getBytes(),
//                "HmacSHA1");
//        sha512Hmac.init(keySpec);
//
//        byte[] result = sha512Hmac.doFinal("s".getBytes());
//        int blocks_needed = (cipher.getKeyLength() + result.length - 1) / result.length ;// len(randkey)
//        byte[] output_block = new byte[0];
//        ByteArrayBuilder bytearray = new ByteArrayBuilder();
//        ByteArrayBuilder okm = new ByteArrayBuilder();
//        for(int count=0; count < blocks_needed; count +=1){
//            Mac mac = Mac.getInstance("HmacSHA1");
//            bytearray.write(output_block);
//            bytearray.write("ss-subkey".getBytes());
//            SecretKeySpec spec = new SecretKeySpec(
//                    bytearray.toByteArray(),
//                    "HmacSHA1");
//            sha512Hmac.init(keySpec);
//            output_block = mac.doFinal(result);
//            okm.write(output_block);
//            bytearray.release();
//        }

        byte[] a = intToLittleEndian(5876);
        byte[] b = intToBigEndian2(23);
        System.out.println("result");
    }
}
