package cn.wowspeeder.encryption;

import io.netty.buffer.ByteBuf;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

/**
 * crypt 加密
 *
 * @author zhaohui
 */
public interface ICrypt {

    void isForUdp(boolean isForUdp);


    default public void encrypt(byte[] data, int length, ByteArrayOutputStream stream) throws Exception  {
        byte[] d = Arrays.copyOfRange(data,0,length);
        encrypt(d, stream);
    }

    default public void encrypt(byte[] data, ByteArrayOutputStream stream) throws Exception{
        byte[] ret;
        ret = encrypt(data);
        stream.write(ret, 0, ret.length);
    }

    default public void decrypt(byte[] data, ByteArrayOutputStream stream) throws Exception {
        byte[] ret;
        ret = decrypt(data);
        stream.write(ret, 0, ret.length);
    }

    default public void decrypt(byte[] data, int length, ByteArrayOutputStream stream) throws Exception {
        byte[] d = Arrays.copyOfRange(data,0,length);
        decrypt(d, stream);
    }

    default byte[] encrypt(byte[] data) throws Exception{

        ByteArrayOutputStream _remoteOutStream = null;
        try {
            _remoteOutStream = new ByteArrayOutputStream(64 * 1024);
            encrypt(data, _remoteOutStream);
            data = _remoteOutStream.toByteArray();

        } finally {
            if (_remoteOutStream != null) {
                try {
                    _remoteOutStream.close();
                } catch (IOException e) {
                }
            }
        }
        return data;
    }

    default byte[] decrypt(byte[] data) throws Exception{
        ByteArrayOutputStream _localOutStream = null;
        try {
            _localOutStream = new ByteArrayOutputStream(64 * 1024);
            decrypt(data, _localOutStream);
            data = _localOutStream.toByteArray();
        } finally {
            if (_localOutStream != null) {
                try {
                    _localOutStream.close();
                } catch (IOException e) {
                }
            }
        }
        return data;
    }

    // 互为对偶
}
