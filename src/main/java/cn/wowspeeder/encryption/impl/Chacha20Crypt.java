package cn.wowspeeder.encryption.impl;

import cn.wowspeeder.encryption.CryptSteamBase;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
//import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.Pack;

public class Chacha20Crypt  extends CryptSteamBase {
    public final static String CIPHER_CHACHA20 = "chacha20";
    public final static String CIPHER_CHACHA20_IETF = "chacha20-ietf";
    public final static String CIPHER_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305";

    public static Map<String, String> getCiphers() {
        Map<String, String> ciphers = new HashMap<>();
//        ciphers.put(CIPHER_CHACHA20, Chacha20Crypt.class.getName());
//        ciphers.put(CIPHER_CHACHA20_IETF, Chacha20Crypt.class.getName());
//        ciphers.put(CIPHER_CHACHA20_IETF_POLY1305, Chacha20Crypt.class.getName());
        return ciphers;
    }

    public Chacha20Crypt(String name, String password) {
        super(name, password);
    }

    @Override
    protected StreamCipher getCipher(boolean isEncrypted) throws InvalidAlgorithmParameterException {
        if (_name.equals(CIPHER_CHACHA20)) {
            return new ChaChaEngine();
        }
        else if (_name.equals(CIPHER_CHACHA20_IETF)) {
            return new ChaCha7539Engine();
        }
        else if (_name.equals(CIPHER_CHACHA20_IETF_POLY1305)) {
            System.out.println(_name);
            ChaCha20Poly1305 engine = new ChaCha20Poly1305(new MyChaCha7539Engine());
//            final KeyParameter myKey = new KeyParameter(Hex.decode(pTestCase.theKey));
//            final byte[] myIV = Hex.decode(pTestCase.theIV);
//            final ParametersWithIV myIVParms = new ParametersWithIV(myKey, myIV);
//            AEADParameters myAEADParms = new AEADParameters(myKey, 0, myIV, myAAD);
//
            return engine;
        }

        return null;
    }

    @Override
    protected SecretKey getKey() {
        return new SecretKeySpec(_ssKey.getEncoded(), "AES");
    }

    @Override
    protected void _encrypt(byte[] data, ByteArrayOutputStream stream) {
        int noBytesProcessed;
        byte[] buffer = new byte[data.length];

        noBytesProcessed = encCipher.processBytes(data, 0, data.length, buffer, 0);
        stream.write(buffer, 0, noBytesProcessed);
    }

    @Override
    protected void _decrypt(byte[] data, ByteArrayOutputStream stream) {
        int BytesProcessedNum;
        byte[] buffer = new byte[data.length];
        BytesProcessedNum = decCipher.processBytes(data, 0, data.length, buffer, 0);
        stream.write(buffer, 0, BytesProcessedNum);

    }

    @Override
    public int getKeyLength() {
        if (_name.equals(CIPHER_CHACHA20) || _name.equals(CIPHER_CHACHA20_IETF) || _name.equals(CIPHER_CHACHA20_IETF_POLY1305)) {
            return 32;
        }
        return 0;
    }

    @Override
    public int getIVLength() {
        if (_name.equals(CIPHER_CHACHA20)) {
            return 8;
        }
        else if (_name.equals(CIPHER_CHACHA20_IETF)) {
            return 12;
        }
        else if (_name.equals(CIPHER_CHACHA20_IETF_POLY1305)) {
            return 32;
        }
        return 0;
    }
}
