package cn.wowspeeder.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.buffer.ByteBuf;

public class CryptUtil {

    private static Logger logger = LoggerFactory.getLogger(CryptUtil.class);

    public static byte[] encrypt(ICrypt crypt, Object msg) throws Exception {
        ByteBuf bytebuff = (ByteBuf) msg;
        int len = bytebuff.readableBytes();
        byte[] arr = new byte[len];
        bytebuff.getBytes(0, arr);
        return crypt.encrypt(arr);
    }

    public static byte[] decrypt(ICrypt crypt, Object msg) throws Exception {

        ByteBuf bytebuff = (ByteBuf) msg;
        int len = bytebuff.readableBytes();
        byte[] arr = new byte[len];
        bytebuff.getBytes(0, arr);
        return crypt.decrypt(arr);

    }

}
