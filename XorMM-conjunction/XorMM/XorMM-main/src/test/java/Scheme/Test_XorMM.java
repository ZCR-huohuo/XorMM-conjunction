package Scheme;
import Client.entity.KV;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.HashSet;
import Server.server;
import util.AESUtil;
import util.Hash;
import Client.Xor_conjuction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays; // 增加了 Arrays 类的导入

public class Test_XorMM {

    public static KV[] kv_list;
    public static HashSet<String> uniqueKeys;
    public static int maxValueNumber = Integer.MIN_VALUE;
    public static int maxCounter = Integer.MIN_VALUE; // 用于记录最大 counter 值
    public static ArrayList<Integer> matchingIndices = new ArrayList<>(); // 用于存储匹配的 i 值
    public static void main(String[] args) throws Exception {
        //maximum volume length
        int MAX_VOLUME_LENGTH = (int) Math.pow(2, 5);
        int XOR_LEVEL = (int) Math.ceil(Math.log(MAX_VOLUME_LENGTH) / Math.log(3.0));//GGM Tree level for xor hash

        //data size
        int power_size = 10;
        int ELEMENT_SIZE = (int) Math.pow(2, power_size);

        //storage size
        int beta = 0;//parameter for xor hash
        int STORAGE_XOR = (int) Math.floor(((ELEMENT_SIZE * 1.23) + beta) / 3);

        //Search key
        String search_key = "key_s_3";


        //initialize a database
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream("C:\\Users\\周超然\\Desktop\\XorMM-conjunction\\XorMM\\XorMM-main\\KV_LIST_10_5.dat"));
            kv_list = (KV[]) in.readObject();
            in.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        // 检查 kv_list 是否初始化成功
        if (kv_list == null) {
            System.err.println("Error: kv_list is null. Please check the file or data format.");
            return;  // 直接返回，避免后续空指针错误
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

        // 输出统计结果
        System.out.println("不同的 key 数量: " + uniqueKeys.size());
        System.out.println("最大 counter 值: " + maxCounter);
        System.out.println("最大的 value 中的数字部分: " + maxValueNumber);


// 输出 kv_list 数组的内容
        System.out.println("-------- kv_list 数组内容 --------");
        for (KV kv : kv_list) {
            if (kv != null) {
//                System.out.println("Key: " + kv.key + ", Value: " + kv.value + ", Counter: " + kv.counter);
            }
        }
        System.out.println("----------------------------------");

        System.out.println("---------------------XorMM scheme(our scheme)---------------------");

        //setup phase
        Xor_conjuction xor = new Xor_conjuction(beta);
        xor.XorMM_setup(kv_list, XOR_LEVEL);

        long K_d = xor.Get_K_d();
        int K_e = xor.Get_K_e();

        byte[][] xor_EMM = xor.Get_EMM();


        //query phase
        server xor_server = new server(xor_EMM,MAX_VOLUME_LENGTH, XOR_LEVEL, STORAGE_XOR);//server receives ciphertext

        System.out.println("\nClient is generating token ... keywords:" + (search_key));
        byte[] tk_key = Hash.Get_SHA_256((search_key+K_d).getBytes(StandardCharsets.UTF_8));//search token

        System.out.println("\nServer is searching and then Client decrypts ... ");
        xor_server.Query_Xor(tk_key);//search
        ArrayList<byte[]> C_key = xor_server.Get_C_key();//client receives results
        byte[] K = Hash.Get_Sha_128((K_e+search_key).getBytes(StandardCharsets.UTF_8));

//        for (int i = 0; i < C_key.size(); i++)//decryption
//        {
//            byte[] str_0 = AESUtil.decrypt(K,C_key.get(i));
//            if(str_0!=null){
//                String s = new String(str_0);
//                System.out.println("Result:" + s);
//            }
//        }
        System.out.println("---------------send enc_list and y to server--------------");
        // 修改后的代码：解密并与 enc_list 匹配
        for (int i = 0; i < C_key.size(); i++) // decryption
        {
            byte[] str_0 = AESUtil.decrypt(K, C_key.get(i));
            if (str_0 != null) {
                // 遍历 enc_list，寻找匹配的加密值
                for (int j = 0; j < kv_list.length; j++) {
                    if (Arrays.equals(C_key.get(i), Xor_conjuction.enc_list[j])) {
                        // 如果找到了匹配项，保存 i 的值到 matchingIndices
                        matchingIndices.add(j);
                        break; // 找到匹配的值后，不需要继续遍历 enc_list，跳出内层循环
                    }
                }
                String s = new String(str_0);
                System.out.println("Decrypted result for key: " + s);
            }
        }

        for (int index : matchingIndices) {
//            System.out.println("Matching index: " + index);
            System.out.println("enc_list[" + index + "]: " + Arrays.toString(Xor_conjuction.enc_list[index]));
            System.out.println("y[" + index + "]: " + Arrays.toString(Xor_conjuction.y[index]));
        }
        // 输出匹配的索引值
//        System.out.println("Matching indices: " + matchingIndices);

        xor_server.Store_Server("XorMM");
    }
}
