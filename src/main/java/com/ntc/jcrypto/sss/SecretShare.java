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

package com.ntc.jcrypto.sss;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author nghiatc
 * @since Dec 31, 2019
 * 
 * https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
 */
public class SecretShare {
    private static final Logger log = LoggerFactory.getLogger(SecretShare.class);
    public static final BigInteger PRIME = new BigInteger("2").pow(127).subtract(BigInteger.ONE); // 2^127 - 1
    private Random rand = new SecureRandom();
    
    private int minimum;
    private int shares;
    private List<BigInteger> poly = new ArrayList<>();
    private List<SPoint> points = new ArrayList<>();;

    public SecretShare(int minimum, int shares) {
        if (minimum > shares) {
            throw new ExceptionInInitializerError("Pool secret would be irrecoverable.");
        }
        this.minimum = minimum;
        this.shares = shares;
        // Generates a random shamir pool, the secret poly[0] and the share points.
        for (int i=0; i < minimum; i++) {
            poly.add(randNBit());
        }
        for (int i=1; i <= shares; i++) {
            BigInteger x = new BigInteger(String.valueOf(i));
            BigInteger y = evalAt(poly, x);
            SPoint sp = new SPoint(x, y);
            points.add(sp);
        }
    }

    public int getMinimum() {
        return minimum;
    }

    public int getShares() {
        return shares;
    }

    public List<BigInteger> getPoly() {
        return poly;
    }

    public List<SPoint> getPoints() {
        return points;
    }
    
    private BigInteger randNBit() {
        return new BigInteger(127, rand); // range(0, 2^127 - 1)
    }
    
    private BigInteger evalAt(List<BigInteger> poly, BigInteger x) {
        BigInteger accum = BigInteger.ZERO;
        if (poly != null && !poly.isEmpty()) {
            int size = poly.size();
            for (int i=size-1; i>=0; --i) {
                //Horner's method: y = (ax + b)x + c
                accum = accum.multiply(x).add(poly.get(i)).mod(PRIME);
            }
        }
        //log.info("accum: " + accum.toString());
        return accum;
    }
    
    public BigInteger recoverSecret(List<SPoint> listshares) throws Exception {
        if (listshares == null || listshares.isEmpty()) {
            throw new Exception("listshares is empty");
        }
        if (listshares.size() < minimum) {
            throw new Exception("Need at least "+minimum+" shares");
        }
        return lagrangeInterpolate(listshares);
    }
    
    // Recover the secret from share points
    // calculate f(0) of the given points using Lagrangian interpolation
    private BigInteger lagrangeInterpolate(List<SPoint> listshares) throws Exception {
        BigInteger y = BigInteger.ZERO;
        BigInteger x = BigInteger.ZERO;
        for (int i=0; i<listshares.size(); i++) {
            BigInteger aX = listshares.get(i).getX();
            BigInteger aY = listshares.get(i).getY();
            BigInteger li = BigInteger.ONE;
            for (int j=0; j<listshares.size(); j++) {
                if (i!=j) {
                    // li = li + (x-bX)/(aX-bX)
                    BigInteger bX = listshares.get(j).getX();
                    BigInteger tu = x.subtract(bX);
                    BigInteger mau = aX.subtract(bX).modInverse(PRIME);
                    li = li.multiply(tu).multiply(mau).mod(PRIME);
                }
            }
            y = y.add(li.multiply(aY)).mod(PRIME);
        }
        return y;
    } 
}
