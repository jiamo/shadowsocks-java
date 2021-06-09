package cn.wowspeeder.encryption;


import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;


public class BaseCipher implements ICrypt {



    private static InternalLogger logger = InternalLoggerFactory.getInstance(BaseCipher.class);
    static int KEY_LENGTH;
    static int IV_LENGTH;
    static int test;
    static Class CIPHER = Cipher.class;
    // cache
    HashMap<String, byte[]> cache = new HashMap<>();
    byte[] key;
    byte[] iv;
    protected boolean isForUdp;
    boolean ota;
    Cipher cipher;  // this instance
    protected final Lock decLock = new ReentrantLock();
    protected final Lock encLock = new ReentrantLock();

    public BaseCipher(byte[] key) {
        this(key, false, true);
    }

    public BaseCipher(byte[] key, boolean ota) {
        this(key, ota, true);
    }

    public int getKeyLength () {
        return BaseCipher.KEY_LENGTH;
    }

    public int getIVLength () {
        return BaseCipher.IV_LENGTH;
    }

    public Class getCIPHER(){
        return BaseCipher.CIPHER;
    }

    public BaseCipher(byte[] key, boolean ota, boolean setup_key) {

        if(getKeyLength() > 0 && setup_key){
            if(this.key == null){
                this.key = init(key);
            }
        } else{
            this.key = key;
        }
        iv = null;
        this.ota = ota;
    }

    static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    Object setup_iv(){
        return setup_iv(null);
    }

    Object setup_iv(byte[] iv){
        if(iv == null){
            this.iv = randomBytes(getIVLength());
        }
        else{
            this.iv = iv;
        }
        setup();
        return this;
    }

    void setup(){
        System.out.println("BasicCipher setup");
    }

    public byte[] decrypt(byte[] s){
        return this.cipher.decrypt(s);
    }

    public byte[] encrypt(byte[] s){
        return this.cipher.encrypt(s);
    }

    private byte[] init(byte[] passwordBytes) {
        MessageDigest md = null;
        byte[] keys = new byte[getKeyLength()];
        byte[] temp = null;
        byte[] hash = null;
        int i = 0;

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            logger.error("init error", e);
            return null;
        }

        while (i < keys.length) {
            if (i == 0) {
                hash = md.digest(passwordBytes);
                temp = new byte[passwordBytes.length + hash.length];
            } else {
                System.arraycopy(hash, 0, temp, 0, hash.length);
                System.arraycopy(passwordBytes, 0, temp, hash.length, passwordBytes.length);
                hash = md.digest(temp);
            }
            System.arraycopy(hash, 0, keys, i, hash.length);
            i += hash.length;
        }

        return keys;
    }

    @Override
    public void isForUdp(boolean isForUdp) {
        this.isForUdp = isForUdp;
    }

    public static void main(String[] args) throws Exception {
    }

}
