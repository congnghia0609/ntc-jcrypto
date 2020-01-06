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
import java.util.ArrayList;
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
            //test3();
            
            // test7
            test7();
            
            // test6
            //test6();
            
            // test4
            //test4();
            
            //test5
            //test5();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test7() {
        try {
            String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            SSS sss = new SSS();
            List<String> arr = sss.create2(3, 6, s);
            //System.out.println(arr);
            for (int i=0; i<arr.size(); i++) {
                System.out.println("shares["+i+"]: " + arr.get(i));
            }
            
            System.out.println("secret: " + s);
            System.out.println("secret.length: " + s.length());
            String s1 = sss.combine2(arr.subList(0, 3));
            System.out.println("combines shares 1 length = " + arr.subList(0, 3).size());
            System.out.println("secret: " + s1);
            System.out.println("secret.length: " + s1.length());
            
            String s2 = sss.combine2(arr.subList(3, 6));
            System.out.println("combines shares 2 length = " + arr.subList(3, 6).size());
            System.out.println("secret: " + s2);
            System.out.println("secret.length: " + s2.length());
            
            String s3 = sss.combine2(arr.subList(1, 5));
            System.out.println("combines shares 3 length = " + arr.subList(1, 5).size());
            System.out.println("secret: " + s3);
            System.out.println("secret.length: " + s3.length());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void test6() {
        try {
            String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            SSS sss = new SSS();
            List<String> arr = new ArrayList<>();
            arr.add("-6kRAYzbOJ7Bzix7Ho2MllDFsPWoRn5jJdtjN-Jh6u0=WNAC1C43DgizLFxx9tztNtajaRipLorHCjyVEK7IbCE=rs6Ldl2b1BHMV-g6tostDCGsbzgAD6MRI9E4JHdS1zY=iuX9lmVpMnFmvUihuIZnaA0wo0QgqxJcS61Pd8tDbOY=AgHOXOZ51Ir8DzIcLAGIastwVeYeU46N2yb3F-OVlUM=Sh7Od5Nj4D8mT8ICLUNpJUkNAQnImWkcQGqzobGgN98=ztDxUHU5lqumJhe2PaGuwWJqlcMUAUGEzeqwf9Gi0FE=PJ9HU92KhgSb1gk7110DZWaD0zEinuTzrtZ75Tpdy7g=");
            arr.add("PGnifsn0E47aTPjGROtUIdCeybbeVis7BdJXcr7bhvE=AOX8JqnX6SU61MFUscFYtMXH4u6vXqhs3xscH_mZHxs=iCkv-b1UEtdHHViAcFWXAIK77S3_J4AmPx0YurzrJWI=pGX2-_9iw89cJl94NT1_7xWdmjRLQFm69sG2rnjMQyI=Cr2L8oCqIi9EKR6BCT6c9yx-rmQeCLqdZS71uUfVErI=qQjqe8PR_k4sokN45SozVvvp3xkcKe2h67B7eMbWekQ=zMaw6I4rXjjnd18dCbI_ErD-drdihERmFtwTivu-MpM=WPewg1Il5CzD0T9qQDU9e3473Fe4n5hcXMt9ZgtIPMw=");
            arr.add("tjt0-OscuPvII8MdurlJ7IKt518Dh5CB3Ja6hIUHHG8=g8mf7n0-Yo_AKMRJQnzyWAhlutYMW7xn9ZpoCxFMMts=IGUn5CTH2B0m5LoOkfqpeurC3nikWGHFNOJ3zQoIhms=gQmy8mWlUA6nCy4sP_EhsquFJ_yM0OV3RXW0H6Aki4I=1_m0WCeVZnyGbYi3S-O9Fk8NoxaGIMLU5mYIH1Ho15o=-m8F5ObRHSRd5grwK8ibBE41nKm35eD78bQr_783FVs=MX1GtfXetB9BbvkfeOW7vyyYJAtc6PCFIUsVAElRbDo=NXJemTh4-F9ft64F9jIeLdH5ap8PiqXOOC9RyJf5hzY=");
            arr.add("9KYl1DQKRqkugNhsbmsTr2oGMX4nwMMmkbdolduW52U=fPN17lGFPRNGCXDAmNBCepJED7VdiqznFYagIWK8-KA=X2lgZwYoCsmDcU-AjskA5_ybtmKaLMRj9zmQOm1c8jY=2DsLN-EteKyEUAYQ14qIHRYemEeGAs9Sl9PDLOgzRvY=tyU8vyiIm1WoLe5U2nDQaU2mZlM-cKKeEdZFYz3w4Hs=uoiH1q8rfzqj76Q-WU4rI4-45qjWfg7CLoTWj_HJVGQ=YkjdzOpgxyEpXb20M7ZAwfJarywA2jU42dADDiM4arg=FCBA4qL0rEBbuJMqVNaftWqEEt1s95ZqMLJmEmWNCSQ=");
            arr.add("5SfGYvum00lZyxnKC6F7eu9k8_1vplEe1FKJKlJmwgM=BQuq8pbN4sHyevmpOzW4x-44wvXF0F0EoeI2EoD3naE=K9RtoD7O8hT1Kg3JjoEN7QyhFwgxq1bfm4tBYQEQVaM=wX9HOEqXXEB4bzIfLTqkG2CGqGe0zJkCqnpFCnQBlpI=5lsrk9yqlYvPXN4qWABpte5NYcZuUKE7j26-iDIPdXs=3NRI3z2lXmPpP-lJ9IimWPHJ5SxaIZvCgCBLbtWNzoY=qW8apzgoff0FfN-nsQ1qoX6D15fxXsRVOYDouA79rV4=S5rSKUHeDSH4jxzp7Wtuhbf2-M8PCIHmealP9V43Qhc=");
            arr.add("RNAt2VUwkL4Ip22-pdhoWEP_rUv8N2CSZvAu1_X7Lgo=m7CONLOElJUz1liZ3gNakUw8kgnOl5gXpoIjgNsztz0=KYSIRF6X75jHi36-TLox7g9Cug0akg_QRxMg6lyPtQA=6UOeGwZZIEH1DwGfd2S8ETzRDPLT19imSylh48JK9V8=P9qjc81sVLyxI-fyKpq-vmhcvcSCoLnN7Yh64yFK9SA=26bJwPGErnws19RRjk-m5At3z8QY0VRdZCFOOhD8mMg=FYAI4YJ8r0z7FH59d0p0y7WVxlVOdhWCK2UqnImvNhw=20ozw45I4Wlgnq_8J9RbGXlWU7FHCn7MCdJbezxk-TE=");
            
            System.out.println("secret: " + s);
            System.out.println("secret.length: " + s.length());
            String s1 = sss.combine(arr.subList(0, 3));
            System.out.println("combines shares 1 length = " + arr.subList(0, 3).size());
            System.out.println("secret: " + s1);
            System.out.println("secret.length: " + s1.length());
            
            String s2 = sss.combine(arr.subList(3, 6));
            System.out.println("combines shares 2 length = " + arr.subList(3, 6).size());
            System.out.println("secret: " + s2);
            System.out.println("secret.length: " + s2.length());
            
            String s3 = sss.combine(arr.subList(1, 5));
            System.out.println("combines shares 3 length = " + arr.subList(1, 5).size());
            System.out.println("secret: " + s3);
            System.out.println("secret.length: " + s3.length());
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
            for (int i=0; i<arr.size(); i++) {
                System.out.println("shares["+i+"]: " + arr.get(i));
            }
            
            System.out.println("secret: " + s);
            System.out.println("secret.length: " + s.length());
            String s1 = sss.combine(arr.subList(0, 3));
            System.out.println("combines shares 1 length = " + arr.subList(0, 3).size());
            System.out.println("secret: " + s1);
            System.out.println("secret.length: " + s1.length());
            
            String s2 = sss.combine(arr.subList(1, 5));
            System.out.println("combines shares 2 length = " + arr.subList(1, 5).size());
            System.out.println("secret: " + s2);
            System.out.println("secret.length: " + s2.length());
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
