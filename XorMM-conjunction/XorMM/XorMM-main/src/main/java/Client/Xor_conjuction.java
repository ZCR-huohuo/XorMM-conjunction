package Client;



import Client.entity.KV;
import util.*;
import java.util.HashSet;
import util.AESUtil;
import util.Hash;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.*;


import static Client.Xor_conjuction.xor.xor_list;
import static util.tool.longToBytes;

public class Xor_conjuction {
    private static Random random = new Random();
    public static HashSet<String> uniqueKeys;
    private static int K_e = 012;
    private static long K_d = 123;
    private static int K_p = 678;
    private static int K_m = 345;
    private static int K_i = 234;
    private static int K_z = 456;
    private static int K_f = 567;

    private int beta;
    static int Try_Times;
    public static byte[][] enc_list;
    static byte[][] xv;
    static byte[][] z_k;
    static byte[][] e;
    static byte[][] f;
    static byte[][] q;
    public static byte[][] y;
    static byte[][] xitem;
    static byte[][] xitemone;
    static byte[][] EMM;
    //static byte[][] YMM;
    static byte[][] VMM;
    private static Map<String,byte[]> k_list = new HashMap<String,byte[]>();
    private static Map<String,Integer> leave_map = new HashMap<String,Integer>();
    private static final double SMALL_CONSTANT = 1e-10;
    public static int maxValueNumber = Integer.MIN_VALUE;
    public static int maxCounter = Integer.MIN_VALUE; // 用于记录最大 counter 值
    public Xor_conjuction(int new_beta){
        beta = new_beta;
    }

    public static class YMM {
        public String key;
        public int counter;
        public byte[] e;
        public byte[] y;

        // 构造函数
        public YMM(String key, int counter, byte[] e, byte[] y) {
            this.key = key;
            this.counter = counter;
            this.e = e;
            this.y = y;
        }
    }

    // 辅助方法：将 byte[] 切分为子数组
    public static byte[] sliceArray(byte[] array, int start, int end) {
        byte[] slice = new byte[end - start];
        for (int i = 0; i < slice.length; i++) {
            slice[i] = array[start + i];
        }
        return slice;
    }

    public static class xor {

        public static xor[] xor_list;
        public byte[] enc_list;
        public byte[] y;

        // 构造函数
        public xor( byte[] enc_list, byte[] y) {

            this.enc_list = enc_list;
            this.y = y;
        }
    }

    //the setup algorithm for XorMM scheme
    public void XorMM_setup(KV[] kv_list, int level) throws Exception {
        int table_size = (int) Math.floor(((kv_list.length * 1.23) + beta) / 3);
        EMM = new byte[table_size * 3][];
        enc_list = new byte[kv_list.length][];
        e = new byte[kv_list.length][];

        // 初始化 maxValueNumber 为正值，防止负数参与数组创建
        if (maxValueNumber <= 0) {
            maxValueNumber = 1;
        }

        // 使用 HashSet 统计不同 key 的数量
        uniqueKeys = new HashSet<>();
        // 正则表达式，用于从 value 中提取数字
        Pattern pattern = Pattern.compile("\\d+");
        // 遍历 kv_list 数组
        for (KV kv : kv_list) {
            if (kv != null) {
                uniqueKeys.add(kv.key); // 将 key 添加到 HashSet 中，确保 key 是唯一的

                // 更新最大 counter 值
                if (kv.counter > maxCounter) {
                    maxCounter = kv.counter;
                }

                // 更新字典序最大的 value 中的数字部分
                if (kv.value != null) {
                    Matcher matcher = pattern.matcher(kv.value);
                    if (matcher.find()) {
                        int valueNumber = Integer.parseInt(matcher.group());
                        if (valueNumber > maxValueNumber) {
                            maxValueNumber = valueNumber;
                        }
                    }
                }
            }
        }

//        // 输出统计结果
//        System.out.println("不同的 key 数量: " + uniqueKeys.size());
//        System.out.println("最大 counter 值: " + maxCounter);
//        System.out.println("最大的 value 中的数字部分: " + maxValueNumber);

        xv = new byte[kv_list.length][];
        z_k = new byte[kv_list.length][];
        f = new byte[kv_list.length][];
        q = new byte[kv_list.length][];
        y = new byte[kv_list.length][];
        // 初始化 xitem 数组的每一行
        xitem = new byte[uniqueKeys.size()][maxValueNumber]; // Ensure 2D array is properly sized


        // 初始化 xitemone 数组
        xitemone = new byte[kv_list.length][];
        for (int i = 0; i < kv_list.length; i++) {
            xitemone[i] = new byte[maxValueNumber];  // 也为每一行分配列空间
        }
//System.out.println("kv_list: "+kv_list);
        for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_e+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            enc_list[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
            System.out.println("enc_list: "+Arrays.toString(enc_list[i]));
        }

         for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_i+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            xv[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
//             System.out.println("xv: " + Arrays.toString(xv[i]));

         }



         for (int i = 0; i < kv_list.length; i++) {
            byte[] K_1;
            if(k_list.containsKey(kv_list[i].key))
                K_1 = k_list.get(kv_list[i].key);
            else {
                K_1 = Hash.Get_Sha_128((K_z+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K_1);
            }
            z_k[i] = AESUtil.encrypt(K_1,(kv_list[i].key + "," + i).getBytes());
//             System.out.println("z_k: " + Arrays.toString(z_k[i]));
        }


         for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_d+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            e[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
//            System.out.println("e" + e[i]);
        }

         for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_f+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            f[i] = AESUtil.encrypt(K,(kv_list[i].key).getBytes());
//             System.out.println("f: "+f[i]);
        }




         for (int i = 0; i < maxValueNumber; i++) {
             byte[] K_2;
             K_2 = Hash.Get_Sha_128((K_z + "i").getBytes());
           q[i] = AESUtil.encrypt(K_2,(kv_list[1].key + "i").getBytes());
        }



//System.out.println("----------------------------------");
        // 主处理逻辑
        for (int i = 0; i < xv.length; i++) {
            // 防止数组访问越界，先进行边界检查
            {
                // 初始化 double 变量
                double adjusted_zk_1 = 0.0;
                double adjusted_zk_2 = 0.0;
                double xv_i_1 = 0.0;
                double xv_i_2 = 0.0;

                // 确保每个 result 数组包含两个元素（用于存储两个 double 结果）
                double[] result = new double[2];

                // 将 z_k[i] 的 16 字节分为前 8 字节和后 8 字节，并转换为 double
                adjusted_zk_1 = byteArrayToDouble(sliceArray(z_k[i], 0, 8));
                adjusted_zk_2 = byteArrayToDouble(sliceArray(z_k[i], 8, 16));

                // 将 xv[i] 的 16 字节分为前 8 字节和后 8 字节，并转换为 double
                xv_i_1 = byteArrayToDouble(sliceArray(xv[i], 0, 8));
                xv_i_2 = byteArrayToDouble(sliceArray(xv[i], 8, 16));

                // 计算 result[0] 和 result[1]
                result[0] = xv_i_1 / adjusted_zk_1;
                result[1] = xv_i_2 / adjusted_zk_2;

                // 将两个结果分别转换为 byte[] 并合并为一个 16 字节的数组
                byte[] y_1 = doubleToByteArray(result[0]);
                byte[] y_2 = doubleToByteArray(result[1]);

                // 将 y_1 和 y_2 合并为一个新的 byte[]，长度为 16
                y[i] = new byte[16];
                System.arraycopy(y_1, 0, y[i], 0, 8);
                System.arraycopy(y_2, 0, y[i], 8, 8);

//                System.out.println("y: " + Arrays.toString(y[i]));
            }
        }


        for (int z = 0; z < uniqueKeys.size(); z++) {
            for (int j = 0; j < maxValueNumber; j++) {
                // 计算结果
                double xitem_t = byteArrayToDouble(xv[j]) * byteArrayToDouble(f[z]);
                // 将 double 转换为 long
                long bits = Double.doubleToRawLongBits(xitem_t);
                // 取 long 的某些字节部分存储为 byte
                xitem[z][j] = (byte) (bits & 0xFF); // 或者用 (bits >> 8) & 0xFF 取不同的字节
//                System.out.println("xitem: " + xitem[z][j]);
            }
        }


//System.out.println("----------------------------------");
                 // 将二维数组 xitem 转换为一维数组 xitemone
        int totalElements = uniqueKeys.size() * maxValueNumber; // 一维数组的总长度
        double[] xitemone = new double[totalElements]; // 新的一维数组
// 用于将二维数组的元素传输到一维数组
        int index = 0; // 一维数组 xitemone 的索引
        for (int i = 0; i < uniqueKeys.size(); i++) {
            for (int j = 0; j < maxValueNumber; j++) {
                xitemone[index] = xitem[i][j];  // 先将值放入 xitemone
//                System.out.println("xitem: " + xitem[i][j]); // 打印 xitem[i][j] 的值
//                System.out.println("xitemone[" + index + "]: " + xitemone[index]); // 打印赋值后的 xitemone 当前索引处的值
                index++; // 最后再自增索引
            }
        }



        YMM[] ymm_list = new YMM[kv_list.length];

        for (int i = 0; i < kv_list.length; i++) {
            // 从kv_list中获取key和counter，e[i]和y[i]分别从e和y数组中获取
            ymm_list[i] = new YMM(kv_list[i].key, kv_list[i].counter, enc_list[i], y[i]);
//            System.out.println("YMM: " + ymm_list[i].key + ", " + ymm_list[i].counter + ", " + Arrays.toString(ymm_list[i].e) + ", " + Arrays.toString(ymm_list[i].y));
        }

        xor_list = new xor[kv_list.length]; // 创建 xor 类的数组

        for (int i = 0; i < kv_list.length; i++) {
            // 假设 enc_list[i] 和 y[i] 是两个 byte[] 数组
            xor_list[i] = new xor(enc_list[i], y[i]); // 将 enc_list[i] 和 y[i] 传入 xor 构造函数
//            System.out.println("XOR: enc_list=" + Arrays.toString(xor_list[i].enc_list) + ", y=" + Arrays.toString(xor_list[i].y));
            // 打印调试信息
        }

        MappingStep1(ymm_list,table_size,level);
        for(int i=0;i<ymm_list.length;i++){
            if(EMM[i]==null){
                EMM[i] = Hash.Get_Sha_128(longToBytes(random.nextInt(1000)));
            }
        }
    }

    // 修改后的 byteArrayToDouble 方法：使用 ByteBuffer 更安全地处理 byte[] 到 double 的转换
//    public static double byteArrayToDouble(byte[] byteArray) {
//        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
//        return buffer.getDouble();  // 按照 IEEE 754 规范将 byte[] 解析为 double
//    }

    // double 转 byte[]
    private byte[] doubleToByteArray(double value) {
        return ByteBuffer.allocate(8).putDouble(value).array();
    }

//    private byte[] doubleToByteArray(double value) {
//        return ByteBuffer.allocate(8).putDouble(value).array();
//    }
//
    public static double byteArrayToDouble(byte[] byteArray) {
        double result = 0;
        for (int i = 0; i < byteArray.length; i++) {
            result += (byteArray[i] & 0xFF) * Math.pow(256, i);  // 按位计算，将 byte[] 转换为 double 值
        }
        return result;  // 确保返回 result
    }



//    MappingStep2(kv_list,table_size2,level2);
//        for(int i=0;i<EMM.length;i++){
//                if(EMM[i]==null){
//                    EMM[i] = Hash.Get_Sha_128(longToBytes(random.nextInt(1000)));
//                }
//        }
//    }



    public void XorMM_Success(KV[] kv_list, int level) throws Exception {
        Try_Times = 0;
        int table_size = (int) Math.floor(((kv_list.length * 1.23) + beta) / 3);
        EMM = new byte[table_size * 3][];
        enc_list = new byte[kv_list.length][];

        for (int i = 0; i < kv_list.length; i++) {
            enc_list[i] = (kv_list[i].value).getBytes();
        }

        // 重新创建 ymm_list
        YMM[] ymm_list = new YMM[kv_list.length];
        for (int i = 0; i < kv_list.length; i++) {
            ymm_list[i] = new YMM(kv_list[i].key, kv_list[i].counter, enc_list[i], y[i]);
        }

        MappingStep1(ymm_list, table_size, level);
    }



    //the setup algorithm for VXorMM scheme
//    public void VXorMM_Setup(KV[] kv_list,int level) throws Exception {
//        int table_size = (int) Math.floor(((kv_list.length*1.23)+beta)/3);
//        EMM = new byte[table_size*3][];
//        VMM = new byte[table_size*3][];
//
//        enc_list = new byte[kv_list.length][];
//
//        for (int i = 0; i < kv_list.length; i++) {
//            byte[] K;
//            if(k_list.containsKey(kv_list[i].key))
//                K = k_list.get(kv_list[i].key);
//            else {
//                K = Hash.Get_Sha_128((K_e+kv_list[i].key).getBytes());
//                k_list.put(kv_list[i].key,K);
//            }
//            enc_list[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
//        }
//        MappingStep1(kv_list,table_size,level);
//        for(int i=0;i<EMM.length;i++) {
//            byte[] temp = new byte[16];
//            if (EMM[i]==null) {
//                EMM[i] = Hash.Get_Sha_128(longToBytes(random.nextInt(1000)));
//            }
//            for (int j = 0; j < EMM[i].length; j++)
//                temp[j] = EMM[i][j];
//            VMM[i] = tool.Xor(xor_hom.Gen_Proof(temp, K_p), Hash.Get_Sha_128((K_m+","+i).getBytes()));
//        }
//    }



        void MappingStep1(YMM[] ymm_list, int table_size, int level) {
        int arrayLength = table_size * 3;
        int blockLength = table_size;
        long[] reverseOrder = new long[arrayLength];
        byte[] reverseH = new byte[arrayLength];
        int HASHES = 3;
        int reverseOrderPos;



        do {
            reverseOrderPos = 0;
            leave_map.clear();
            GGM.clear();
            K_d = random.nextLong();
            byte[] t2count = new byte[arrayLength];
            long[] t2 = new long[arrayLength];



            for (int i = 0; i < ymm_list.length; i++) {
                long k = i;
                for (int hi = 0; hi < HASHES; hi++) {
                    String ys = ymm_list[(int) k].key + "," + ymm_list[(int) k].counter;
//                    System.out.println("ys: " +ys);
                    String y0 = ys + "," + hi;
//                    System.out.println("y0: " +y0);
                    int Node, current;
                    if (leave_map.containsKey(y0)) {
                        current = leave_map.get(y0);
                    } else {
                        byte[] yv = GGM.Tri_GGM_Path(Hash.Get_SHA_256((ymm_list[(int) k].key + K_d).getBytes()), level, tool.TtS(ymm_list[(int) k].counter, 3, level));
//                        System.out.println("yv: " +yv);
                        current = GGM.Map2Range(Arrays.copyOfRange(yv, 1, 9), table_size, 0);
                        leave_map.put(y0, current);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 11, 19), table_size, 1);
                        leave_map.put(ys + ",1", Node);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 21, 29), table_size, 2);
                        leave_map.put(ys + ",2", Node);
                    }
                    int h = current;
                    t2[h] ^= k;
                    if (t2count[h] > 120) {
                        throw new IllegalArgumentException();
                    }
                    t2count[h]++;
                }
            }



            int[][] alone = new int[HASHES][blockLength];
            int[] alonePos = new int[HASHES];
            for (int nextAlone = 0; nextAlone < HASHES; nextAlone++) {
                for (int i = 0; i < blockLength; i++) {
                    if (t2count[nextAlone * blockLength + i] == 1) {
                        alone[nextAlone][alonePos[nextAlone]++] = nextAlone * blockLength + i;
                    }
                }
            }
            int found = -1;
            while (true) {
                int i = -1;
                for (int hi = 0; hi < HASHES; hi++) {
                    if (alonePos[hi] > 0) {
                        i = alone[hi][--alonePos[hi]];
                        found = hi;
                        break;
                    }
                }
                if (i == -1) {
                    break;
                }
                if (t2count[i] <= 0) {
                    continue;
                }
                long k = t2[i];
                if (t2count[i] != 1) {
                    throw new AssertionError();
                }
                --t2count[i];
                for (int hi = 0; hi < HASHES; hi++) {
                    if (hi != found) {
//                        Integer mapValue = leave_map.get(ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
////                        System.out.println("mapValue: " +mapValue);
//                        if (mapValue == null) {
//                            // 可以选择抛出更明确的异常或进行其他逻辑处理
//                            throw new IllegalStateException("Map does not contain the key: " + ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
//                        }
                        int h = leave_map.get(ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
//                        System.out.println("h: " +h);
                        int newCount = --t2count[h];
                        if (newCount == 1) {
                            alone[hi][alonePos[hi]++] = h;
                        }
                        t2[h] ^= k;
                    }
                }
                reverseOrder[reverseOrderPos] = k;
                reverseH[reverseOrderPos] = (byte) found;
                reverseOrderPos++;
            }



            Try_Times++;
        } while (reverseOrderPos != ymm_list.length);



        for (int i = reverseOrderPos - 1; i >= 0; i--) {
            int k = (int) reverseOrder[i];
//            System.out.println("k: " +k);
            int found = reverseH[i];
            int change = -1;
//            xor.xor_list[k] = enc_list[k];
//            System.out.println("enc: " +enc_list[k]);
            byte[] xor_x = enc_list[k];
            for (int hi = 0; hi < HASHES; hi++) {
                Integer h = leave_map.get(ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
//                System.out.println("h: " +h);
                if (h == null) {
                    // 处理null情况，可以打印日志、抛出异常，或者赋予默认值
//                    System.out.println("Key not found: " + e[i] + "," + y[i]);
                    continue; // 或者 break，或者赋予 h 一个默认值
                }
                if (found == hi) {
                    change = h;
                } else {
                    if (EMM[h] == null) {
                        EMM[h] = Hash.Get_Sha_128(longToBytes(random.nextInt(10000)));
                    }
//                    System.out.println("EMM11: " +EMM[h]);
                    xor_x = tool.Xor(xor_x, EMM[h]);

//                    System.out.println("xor_x: " +xor_x);
                }
            }
            EMM[change] = xor_x;
//            System.out.println("EMM: " +EMM[change]);
        }
    }

    void MappingStep2(YMM[] xitem, int table_size, int level) throws UnsupportedEncodingException {
        int arrayLength = table_size * 3;
        int blockLength = table_size;
        long[] reverseOrder = new long[arrayLength];
        byte[] reverseH = new byte[arrayLength];
        int HASHES = 3;
        int reverseOrderPos;



        do {
            reverseOrderPos = 0;
            leave_map.clear();
            GGM.clear();
            K_d = random.nextLong();
            byte[] t2count = new byte[arrayLength];
            long[] t2 = new long[arrayLength];



            for (int i = 0; i < xitemone.length; i++) {
                long k = i;
                for (int hi = 0; hi < HASHES; hi++) {
                    String ys = new String(xitemone[(int) k], "UTF-8");  // 假设你的字节数组使用 UTF-8 编码
                    String y0 = ys + "," + hi;
                    int Node, current;
                    if (leave_map.containsKey(y0)) {
                        current = leave_map.get(y0);
                    } else {
                        String xitemStr = new String(xitemone[(int) k], "UTF-8");  // 假设 byte[] 是 UTF-8 编码
                        int xitemInt = Integer.parseInt(xitemStr);  // 将字符串转换为 int
                        byte[] yv = GGM.Tri_GGM_Path(Hash.Get_SHA_256((xitemStr + K_d).getBytes()), level, tool.TtS(xitemInt, 3, level));

                        current = GGM.Map2Range(Arrays.copyOfRange(yv, 1, 9), table_size, 0);
                        leave_map.put(y0, current);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 11, 19), table_size, 1);
                        leave_map.put(ys + ",1", Node);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 21, 29), table_size, 2);
                        leave_map.put(ys + ",2", Node);
                    }
                    int h = current;
                    t2[h] ^= k;
                    if (t2count[h] > 120) {
                        throw new IllegalArgumentException();
                    }
                    t2count[h]++;
                }
            }



            int[][] alone = new int[HASHES][blockLength];
            int[] alonePos = new int[HASHES];
            for (int nextAlone = 0; nextAlone < HASHES; nextAlone++) {
                for (int i = 0; i < blockLength; i++) {
                    if (t2count[nextAlone * blockLength + i] == 1) {
                        alone[nextAlone][alonePos[nextAlone]++] = nextAlone * blockLength + i;
                    }
                }
            }
            int found = -1;
            while (true) {
                int i = -1;
                for (int hi = 0; hi < HASHES; hi++) {
                    if (alonePos[hi] > 0) {
                        i = alone[hi][--alonePos[hi]];
                        found = hi;
                        break;
                    }
                }
                if (i == -1) {
                    break;
                }
                if (t2count[i] <= 0) {
                    continue;
                }
                long k = t2[i];
                if (t2count[i] != 1) {
                    throw new AssertionError();
                }
                --t2count[i];
                for (int hi = 0; hi < HASHES; hi++) {
                    if (hi != found) {
                        String xitemStr = new String(xitemone[(int) k], "UTF-8");  // 将 byte[] 转换为 String
                        int h = leave_map.get(xitemStr + hi);  // 进行字符串拼接后，再从 map 中获取
                        int newCount = --t2count[h];
                        if (newCount == 1) {
                            alone[hi][alonePos[hi]++] = h;
                        }
                        t2[h] ^= k;
                    }
                }
                reverseOrder[reverseOrderPos] = k;
                reverseH[reverseOrderPos] = (byte) found;
                reverseOrderPos++;
            }



            Try_Times++;
        } while (reverseOrderPos != xitemone.length);



        for (int i = reverseOrderPos - 1; i >= 0; i--) {
            int k = (int) reverseOrder[i];
            int found = reverseH[i];
            int change = -1;
            byte[] xor = enc_list[k];
            for (int hi = 0; hi < HASHES; hi++) {
                int h = leave_map.get(xitemone[(int) k]);
                if (found == hi) {
                    change = h;
                } else {
                    if (EMM[h] == null) {
                        EMM[h] = Hash.Get_Sha_128(longToBytes(random.nextInt(10000)));
                    }
                    xor = tool.Xor(xor, EMM[h]);
                }
            }
            EMM[change] = xor;
        }
    }
//sdsdsdsdkl；
//
//    public static Object[] generateToken(String key1) throws UnsupportedEncodingException {
//        byte[] tk_key = Hash.Get_SHA_256((search_key+K_d).getBytes(StandardCharsets.UTF_8));
//        String[][] xtoken = new String[][]; // 初始化 xtoken
//
//        // 生成 xtoken
//        for (int j = 0; j < l; j++) {
//            for (int c = 1; c < s; c++) {
//                // 将 byte[] 转换为 String，假设是 UTF-8 编码
//                String qStr = new String(q[j], "UTF-8");
//                String fStr = new String(f[c], "UTF-8");
//// 然后将它们拼接并存储到 xtoken[j][c]
//                xtoken[j][c] = qStr + fStr;  // 将两个字符串拼接
//
//            }
//        }
//    }

    public long Get_K_d(){
        return K_d;
    }
////
    public int Get_K_e() { return K_e; }

    public int Get_K_p(){ return K_p; }

    public int Get_K_m() { return K_m; }

    public int Get_Try_Times(){ return Try_Times; }

    public byte[][] Get_EMM(){ return EMM;}

    public byte[][] Get_VMM(){ return VMM;}

    public void Leave_Map_Clear() { leave_map.clear(); k_list.clear();}




}

