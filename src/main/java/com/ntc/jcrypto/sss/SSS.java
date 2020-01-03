/*
 * Copyright 2020 nghiatc.
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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import javax.xml.bind.DatatypeConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author nghiatc
 * @since Jan 3, 2020
 */
public class SSS {
    private static final Logger log = LoggerFactory.getLogger(SSS.class);
    
    private static final BigInteger PRIME = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639747");
    private Random rand = new SecureRandom();
    
    // Returns a new arary of secret shares (encoding x,y pairs as base64 strings)
    // created by Shamir's Secret Sharing Algorithm requring a minimum number of
    // share to recreate, of length shares, from the input secret raw as a string
    public List<String> create(int minimum, int shares, String secret) {
        // Verify minimum isn't greater than shares; there is no way to recreate
        // the original polynomial in our current setup, therefore it doesn't make
        // sense to generate fewer shares than are needed to reconstruct the secret.
        List<String> rs = new ArrayList<>();
        if (minimum > shares) {
            throw new ExceptionInInitializerError("cannot require more shares then existing");
        }
        
        // Convert the secret to its respective 256-bit big.Int representation
        List<BigInteger> secrets = splitSecretToBigInt(secret);
        System.out.println("====================== create ======================");
        System.out.println(secrets);
        
        // List of currently used numbers in the polynomial
        List<BigInteger> numbers = new ArrayList<>();
        numbers.add(BigInteger.ZERO);
        
        // Create the polynomial of degree (minimum - 1); that is, the highest
        // order term is (minimum-1), though as there is a constant term with
        // order 0, there are (minimum) number of coefficients.
        //
        // However, the polynomial object is a 2d array, because we are constructing
        // a different polynomial for each part of the secret
        // polynomial[parts][minimum]
        BigInteger[][] polynomial = new BigInteger[secrets.size()][minimum];
        for (int i=0; i<secrets.size(); i++) {
            polynomial[i][0] = secrets.get(i);
            for (int j=1; j<minimum; j++) {
                // Each coefficient should be unique
                BigInteger number = random();
                while (inNumbers(numbers, number)) {
                    number = random();
                }
                numbers.add(number);
                
                polynomial[i][j] = number;
            }
        }
        //System.out.println("====================== polynomial ======================");
        //System.out.println(Arrays.deepToString(polynomial));
        
        // Create the secrets object; this holds the (x, y) points of each share.
        // Again, because secret is an array, each share could have multiple parts
        // over which we are computing Shamir's Algorithm. The last dimension is
        // always two, as it is storing an x, y pair of points.
        //
        // Note: this array is technically unnecessary due to creating result
        // in the inner loop. Can disappear later if desired. [TODO]
        //
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares][secrets.size()][2];
        
        // For every share...
        for (int i=0; i<shares; i++) {
            String s = "";
            // ...and every part of the secret...
            for (int j=0; j<secrets.size(); j++) {
                // ...generate a new x-coordinate...
                BigInteger number = random();
                while (inNumbers(numbers, number)) {
                    number = random();
                }
                numbers.add(number);
                
                // ...and evaluate the polynomial at that point...
                points[i][j][0] = number;
                points[i][j][1] = evaluatePolynomial(polynomial, j, number);
                
                // ...add it to results...
                s += toBase64(points[i][j][0]);
                //System.out.println("x[share-"+i+"][part-"+j+"]: " + points[i][j][0].toString(10));
                s += toBase64(points[i][j][1]);
                //System.out.println("y[share-"+i+"][part-"+j+"]: " + points[i][j][1].toString(10));
            }
            rs.add(s);
        }
        //System.out.println("====================== create ======================");
        //System.out.println(Arrays.deepToString(points));
        return rs;
    }
    
    // Takes a string array of shares encoded in base64 created via Shamir's
    // Algorithm; each string must be of equal length of a multiple of 88 characters
    // as a single 88 character share is a pair of 256-bit numbers (x, y).
    // Note: the polynomial will converge if the specified minimum number of shares
    //       or more are passed to this function. Passing thus does not affect it
    //       Passing fewer however, simply means that the returned secret is wrong.
    public String combine(List<String> shares) throws Exception {
        String rs = "";
        if (shares == null || shares.isEmpty()) {
            throw new Exception("shares is NULL or empty");
        }
        
        // Recreate the original object of x, y points, based upon number of shares
        // and size of each share (number of parts in the secret).
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares.size()][][];
        
        // For each share...
        for (int i=0; i<shares.size(); i++) {
            // ...ensure that it is valid...
            if (isValidShare(shares.get(i)) == false) {
                throw new Exception("one of the shares is invalid");
            }
            
            // ...find the number of parts it represents...
            String share = shares.get(i);
            int count = share.length() / 88;
            //System.out.println("count: " + count);
            points[i] = new BigInteger[count][];
            
            // ...and for each part, find the x,y pair...
            for (int j=0; j<count; j++) {
                points[i][j] = new BigInteger[2];
                String cshare = share.substring(j*88, (j+1)*88);
                // ...decoding from base 64.
                points[i][j][0] = fromBase64(cshare.substring(0, 44));
                points[i][j][1] = fromBase64(cshare.substring(44, 88));
            }
        }
        //System.out.println("====================== combine ======================");
        //System.out.println(Arrays.deepToString(points));
        
        // Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
        // For each part of the secret (clearest to iterate over)...
        List<BigInteger> secrets = new ArrayList<>();
        int numSecret = points[0].length;
        //System.out.println("numSecret: " + numSecret);
        for (int j=0; j<numSecret; j++) {
            secrets.add(BigInteger.ZERO);
            // ...and every share...
            for (int i=0; i<shares.size(); i++) { // LPI sum loop
                //System.out.println("i: " + i);
                // ...remember the current x and y values...
                BigInteger origin = points[i][j][0];
                BigInteger originy = points[i][j][1];
                BigInteger numerator = BigInteger.ONE; // LPI numerator
                BigInteger denominator = BigInteger.ONE; // LPI denominator
                // ...and for every other point...
                for (int k=0; k<shares.size(); k++) { // LPI product loop
                    if (k != i) {
                        // ...combine them via half products...
                        BigInteger current = points[k][j][0];
                        BigInteger negative = current.multiply(new BigInteger("-1")).mod(PRIME);
                        BigInteger added = origin.subtract(current);
                        numerator = numerator.multiply(negative).mod(PRIME);
                        denominator = denominator.multiply(added).mod(PRIME);
                    }
                }
                
                // LPI product
                // ...multiply together the points (y)(numerator)(denominator)^-1...
                BigInteger working = originy.multiply(numerator).mod(PRIME);
                working = working.multiply(denominator.modInverse(PRIME)).mod(PRIME);
                
                // LPI sum
                BigInteger secret = secrets.get(j);
                secret = secret.add(working).mod(PRIME);
                secrets.set(j, secret);
            }
        }
        
        // ...and return the result!
        System.out.println("====================== combine ======================");
        System.out.println(secrets);
        rs = mergeBigIntToString(secrets);
        return rs;
    }
    
    // https://www.baeldung.com/java-byte-arrays-hex-strings
    public String encodeHexString(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    // https://www.baeldung.com/java-byte-arrays-hex-strings
    public byte[] decodeHexString(String hexString) {
        return DatatypeConverter.parseHexBinary(hexString);
    }
    
    // Converts a byte array into an a 256-bit big.Int, arraied based upon size of
    // the input byte; all values are right-padded to length 256, even if the most
    // significant bit is zero.
    public List<BigInteger> splitSecretToBigInt(String secret) {
        List<BigInteger> rs = new ArrayList<>();
        if (secret != null && !secret.isEmpty()) {
            byte[] sbyte = secret.getBytes(StandardCharsets.UTF_8);
            String hexData = encodeHexString(sbyte);
            //System.out.println("hexData: " + hexData);
            int count = (int) Math.ceil(hexData.length() / 64.0);
            //System.out.println("secret part count: " + count);
            for (int i=0; i<count; i++) {
                if ((i+1)*64 < hexData.length()) {
                    BigInteger bi = new BigInteger(hexData.substring(i*64, (i+1)*64), 16);
                    rs.add(bi);
                } else {
                    String last = hexData.substring(i*64, hexData.length());
                    String pading = "";
                    for (int j=0; j<(64-last.length()); j++) {
                        pading += "0";
                    }
                    last += pading;
                    BigInteger bi = new BigInteger(last, 16);
                    rs.add(bi);
                }
            }
        }
        return rs;
    }
    
    // Converts an array of big.Ints to the original byte array, removing any
    // least significant nulls
    public String mergeBigIntToString(List<BigInteger> secrets) {
        String rs = "";
        String hexData = "";
        for (BigInteger s : secrets) {
            String tmp = s.toString(16);
            //System.out.println("tmp: " + tmp);
            String pading = "";
            for (int j=0; j<(64-tmp.length()); j++) {
                pading += "0";
            }
            hexData = hexData + pading + tmp;
        }
        byte[] byteData = decodeHexString(hexData);
        byteData = trimRight(byteData);
        rs = new String(byteData, StandardCharsets.UTF_8);
        return rs;
    }
    
    // https://stackoverflow.com/questions/17003164/byte-array-with-padding-of-null-bytes-at-the-end-how-to-efficiently-copy-to-sma
    public byte[] trimRight(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }
        return Arrays.copyOf(bytes, i + 1);
    }
    
    // Returns a random number from the range (0, PRIME-1) inclusive
    public BigInteger random() {
        BigInteger rs = new BigInteger(256, rand);
        while (rs.compareTo(PRIME) >= 0) {
            rs = new BigInteger(256, rand);
        }
        return rs;
    }
    
    // inNumbers(array, value) returns boolean whether or not value is in array
    public boolean inNumbers(List<BigInteger> numbers, BigInteger value) {
        for (BigInteger n : numbers) {
            if (n.compareTo(value) == 0) {
                return true;
            }
        }
        return false;
    }
    
    // Compute the polynomial value using Horner's method.
    // https://en.wikipedia.org/wiki/Horner%27s_method
    private BigInteger evaluatePolynomial(BigInteger[][] poly, int part, BigInteger x) {
        BigInteger accum = BigInteger.ZERO;
        int last = poly[part].length - 1;
        accum = poly[part][last];
        for (int i=last-1; i>=0; --i) {
            //Horner's method: y = (ax + b)x + c
            accum = accum.multiply(x).add(poly[part][i]).mod(PRIME);
        }
        //log.info("accum: " + accum.toString());
        return accum;
    }
    
    // https://www.baeldung.com/java-base64-encode-and-decode
    // Returns the big.Int number base10 in base64 representation; note: this is
    // not a string representation; the base64 output is exactly 256 bits long
    public String toBase64(BigInteger number) {
        //return Base64.getUrlEncoder().encodeToString(number.toByteArray());
        return Base64.getEncoder().encodeToString(number.toByteArray());
    }
    
    // Returns the number base64 in base 10 big.Int representation; note: this is
    // not coming from a string representation; the base64 input is exactly 256
    // bits long, and the output is an arbitrary size base 10 integer.
    // Returns -1 on failure
    public BigInteger fromBase64(String number) {
        //return new BigInteger(Base64.getUrlDecoder().decode(number));
        return new BigInteger(Base64.getDecoder().decode(number));
    }
    
    // Takes in a given string to check if it is a valid secret
    // Requirements:
    // 	 Length multiple of 88
    //	 Can decode each 44 character block as base64
    // Returns only success/failure (bool)
    public boolean isValidShare(String candidate) throws Exception {
        if (candidate == null || candidate.isEmpty()) {
            throw new Exception("String is NULL or empty.");
        }
        if (candidate.length()%88 != 0) {
            return false;
        }
        int count = candidate.length() / 44;
        for (int i=0; i<count; i++) {
            String part = candidate.substring(i*44, (i+1)*44);
            BigInteger decode = fromBase64(part);
            // decode < 0 || decode > PRIME ==> false
            if (decode.compareTo(BigInteger.ONE) == -1 || decode.compareTo(PRIME) == 1) {
                return false;
            }
        }
        return true;
    }
    
    
}
