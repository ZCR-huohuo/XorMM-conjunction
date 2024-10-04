package util;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
//这段代码定义了一个名为 xor_hom 的实用程序类，旨在提供与异或（XOR）同态加密相关的功能。
//具体包括初始化映射表、生成证明、字节到位的转换以及位到字节的转换。

public class xor_hom {
    private static byte[][] map_0;
    private static byte[][] map_1;
    private static long time;
    public static void initial(){
        map_0 = new byte[128][];
        map_1 = new byte[128][];
        time = 0;
    }

//生成一个证明（哈希值）用于同态加密
    public static byte[] Gen_Proof(byte[] b, int K_p) {
        byte[] arr = ByteToBit(b);
        byte[] temp = new byte[16];

        for(int i=0;i<arr.length;i++){
            if(arr[i]== (byte)0){
                if(map_0[i]!=null){
                    temp = tool.Xor(temp,map_0[i]);
                }else {
                    byte[] tep  = Hash.Get_Sha_128((K_p+"0"+i).getBytes());
                    temp = tool.Xor(tep,temp);
                    map_0[i] = tep;
                }
            }else{
                if(map_1[i]!=null){
                    temp = tool.Xor(temp,map_1[i]);
                }else {
                    byte[] tep  = Hash.Get_Sha_128((K_p+"1"+i).getBytes());
                    temp = tool.Xor(tep,temp);
                    map_1[i] = tep;
                }
            }
        }

        return temp;
    }

//将字节数组转换为位数组
    public static byte[] ByteToBit(byte[] b) {
        byte[] arr = new byte[b.length * 8];
        for (int i = 0, j = 0; i < b.length; i++) {
            arr[j+7] = (byte) ((b[i] >> 7) & 0x1);
            arr[j + 6] = (byte) ((b[i] >> 6) & 0x1);
            arr[j + 5] = (byte) ((b[i] >> 5) & 0x1);
            arr[j + 4] = (byte) ((b[i] >> 4) & 0x1);
            arr[j + 3] = (byte) ((b[i] >> 3) & 0x1);
            arr[j + 2] = (byte) ((b[i] >> 2) & 0x1);
            arr[j + 1] = (byte) ((b[i] >> 1) & 0x1);
            arr[j + 0] = (byte) ((b[i] >> 0) & 0x1);
            j = j + 8;
        }
        return arr;
    }

//将位数组转换为字节数组
    public static byte[] BitToByte(byte[] byte_list) {
        byte[] tmp = new byte[8];
        byte[] arr = new byte[byte_list.length / 8];
        if (null == byte_list) {
            return null;
        }
        for (int i = 0; i < byte_list.length; ) {
            byte temp = (byte) 0;
            System.arraycopy(byte_list, i, tmp, 0, 8);
            for (int j = 0; j < 8; j++) {
                temp = (byte) (temp | tmp[j] << j);
            }
            arr[i / 8] = temp;
            i = i + 8;
        }
        return arr;
    }

    public static void time_sum(){
        System.out.println("time:"+time);
    }


}
