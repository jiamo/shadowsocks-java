package cn.wowspeeder.encryption;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

public class RC4_MD5_Cipher extends RC4_Cipher {
    static int KEY_LENGTH = 16;
    static int IV_LENGTH = 16;
    public static String CIPHER_RC4_MD5 = "rc4-md5";

    public static Map<String, String> getCiphers() {
        Map<String, String> ciphers = new HashMap<String, String>();
        ciphers.put(CIPHER_RC4_MD5, RC4_MD5_Cipher.class.getName());
        return ciphers;
    }

    public int getKeyLength() {
        return RC4_MD5_Cipher.KEY_LENGTH;
    }

    public RC4_MD5_Cipher(byte[] key) {
        super(key);
    }

    public RC4_MD5_Cipher(byte[] key, boolean ota) {
        super(key, ota);
    }

    public RC4_MD5_Cipher(byte[] key, boolean ota, boolean setup_key) {
        super(key, ota, setup_key);
    }

    public int getIVLength () {
        return RC4_MD5_Cipher.IV_LENGTH;
    }

    public void setup(){
//        System.out.println("StreamCipher... setup");

        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] temp = new byte[key.length + getIVLength()];
            System.arraycopy(key, 0, temp, 0, key.length);
            System.arraycopy(iv, 0, temp, key.length, getIVLength());
            key = md.digest(temp);
        }catch (Exception e){
            e.printStackTrace();
        }
        super.setup();
    }
}
