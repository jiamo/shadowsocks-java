package cn.wowspeeder.encryption;

import com.fasterxml.jackson.core.util.ByteArrayBuilder;

import java.io.IOException;
import java.util.Arrays;

public class StreamCiper extends BaseCipher{

    static int IV_LENGTH = 0;
    Generator<Byte> stream;

    public StreamCiper(byte[] key) {
        super(key);
    }

    public StreamCiper(byte[] key, boolean ota, boolean setup_key) {
        super(key, ota, setup_key);
    }

    public void setup(){
        stream = core();
    }

    public int getIVLength () {
        return StreamCiper.IV_LENGTH;
    }

    public byte[] encrypt(byte[] s){
//        synchronized (encLock){
            // setup 之后应该就一样了。
            ByteArrayBuilder ret = new ByteArrayBuilder();
            if (iv == null) {
//                setup_iv(Arrays.copyOfRange(s, 0, getIVLength()));
                setup_iv();
                if(getIVLength() > 0){
                    ret.write(iv);
                }
            }
            int j =0;
            for(byte i: s){
                byte tmp = stream.get();
//                System.out.println(String.format("%d %d %d", j, i,  tmp));
                ret.write(i ^ tmp);
                j++;
            }
            byte[] r = ret.toByteArray();
            return r;
//        }
    }

    public byte[] decrypt(byte[] s){

//        synchronized (decLock){
            byte[] temp;
            if (iv == null) {
                setup_iv(Arrays.copyOfRange(s, 0, getIVLength()));
                temp = Arrays.copyOfRange(s, getIVLength(), s.length);
            }else{
                temp = s;
            }
    //        return encrypt(temp); // don't use this anymore
            ByteArrayBuilder ret = new ByteArrayBuilder();
            int j = 0;
            for(byte i: temp){
                byte tmp = stream.get();
                ret.write(i ^ tmp);
//                System.out.println(String.format("%d %d %d", j++, i,  tmp));
            }
            return ret.toByteArray();
//        }
    }

    public Generator<Byte> core(){
        // Dynamic working
//        System.out.println("StreamCiper.... core");
        Generator<Byte> n = new Generator<Byte>() {
            @Override
            protected void run() throws Exception {
                while (true) {
                    yield((byte)0);
                }
            }
        };
        return n;
    }
}
