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
import com.ntc.jcrypto.sss.SecretShare;
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
