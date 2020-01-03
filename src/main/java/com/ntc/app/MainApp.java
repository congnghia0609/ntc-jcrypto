/*
 * Copyright 2019 nghiatc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ntc.app;

import com.ntc.jcrypto.sss.SPoint;
import com.ntc.jcrypto.sss.SSS;
import com.ntc.jcrypto.sss.SecretShare;
import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author nghiatc
 * @since Dec 31, 2019
 */
public class MainApp {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            // test1
            //test1();
            
            // test3
            test3();
            
            // test4
            //test4();
            
            //test5
            //test5();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test3() {
        try {
            String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            SSS sss = new SSS();
            List<String> arr = sss.create(3, 6, s);
            //System.out.println(arr);
//            for (int i=0; i<arr.size(); i++) {
//                System.out.println("shares["+i+"]: " + arr.get(i));
//            }
            
            System.out.println("secret: " + s);
            String s1 = sss.combine(arr.subList(0, 3));
            System.out.println("combines shares 1 length = " + arr.subList(0, 3).size());
            System.out.println("secret: " + s1);
            
            String s2 = sss.combine(arr.subList(1, 5));
            System.out.println("combines shares 2 length = " + arr.subList(1, 5).size());
            System.out.println("secret: " + s2);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test5() {
        try {
            SSS sss = new SSS();
            String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            System.out.println("s: " + s);
            // Convert the secret to its respective 256-bit big.Int representation
            List<BigInteger> secrets = sss.splitSecretToBigInt(s);
            String r = sss.mergeBigIntToString(secrets);
            System.out.println("r: " + r);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test4() {
        try {
            SSS sss = new SSS();
            BigInteger bi = new BigInteger("10");
            System.out.println("bi: " + bi.toString(10));
            String s = sss.toBase64(bi);
            System.out.println("s: " + s);
            BigInteger dbi = sss.fromBase64(s);
            System.out.println("dbi: " + dbi.toString(10));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test2() {
        try {
            BigInteger prime = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639747");
            System.out.println("prime=" + prime.toString(2));
            // 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
            // 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
            // 1111111111111111111111111111111111111101000011
            System.out.println("prime.bitLength=" + prime.bitLength()); // 256
            System.out.println("prime.bitCount=" + prime.bitCount()); // 251
            System.out.println("prime.isProbablePrime[10000]=" + prime.isProbablePrime(10000)); // true
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test1() {
        try {
            SecretShare ss = new SecretShare(3, 6);
            System.out.println("Secret: " + ss.getPoly());
            System.out.println("Shares: ");
            List<SPoint> listPoints = ss.getPoints();
            for (SPoint sp : listPoints) {
                System.out.println(sp);
            }
            
            System.out.println("");
            List<SPoint> subset1 = ss.getPoints().subList(0, 3);
            System.out.println("subset1: " + subset1);
            System.out.println("Secret recovered from minimum subset1 of shares: " + ss.recoverSecret(subset1));
            
            System.out.println("");
            List<SPoint> subset2 = ss.getPoints().subList(3, 6);
            System.out.println("subset2: " + subset2);
            System.out.println("Secret recovered from minimum subset2 of shares: " + ss.recoverSecret(subset2));
            
            System.out.println("");
            List<SPoint> subset3 = ss.getPoints().subList(1, 5);
            System.out.println("subset3: " + subset3);
            System.out.println("Secret recovered from minimum subset3 of shares: " + ss.recoverSecret(subset3));
            
//            System.out.println("");
//            List<SPoint> subset4 = ss.getPoints().subList(0, 2);
//            System.out.println("subset4: " + subset4);
//            System.out.println("Secret recovered from minimum subset4 of shares: " + ss.recoverSecret(subset4));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
