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
    
    // Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings)
    // created by Shamir's Secret Sharing Algorithm requiring a minimum number of
    // share to recreate, of length shares, from the input secret raw as a string
    public List<String> create(int minimum, int shares, String secret, boolean isBase64) {
        List<String> rs = new ArrayList<>();
        // Verify minimum isn't greater than shares; there is no way to recreate
        // the original polynomial in our current setup, therefore it doesn't make
        // sense to generate fewer shares than are needed to reconstruct the secret.
        if (minimum > shares) {
            throw new ExceptionInInitializerError("cannot require more shares then existing");
        }
        
        // Convert the secret to its respective 256-bit BigInteger representation
        List<BigInteger> secrets = splitSecretToBigInt(secret);
        
        // List of currently used numbers in the polynomial
        List<BigInteger> numbers = new ArrayList<>();
        numbers.add(BigInteger.ZERO);
        
        // Create the polynomial of degree (minimum - 1); that is, the highest
        // order term is (minimum-1), though as there is a constant term with
        // order 0, there are (minimum) number of coefficients.
        // 
        // However, the polynomial object is a 2d array, because we are constructing
        // a different polynomial for each part of the secret
        // 
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
        
        // Create the secrets object; this holds the (x, y) points of each share.
        // Again, because secret is an array, each share could have multiple parts
        // over which we are computing Shamir's Algorithm. The last dimension is
        // always two, as it is storing an x, y pair of points.
        // 
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares][secrets.size()][2];
        
        // For every share...
        for (int i=0; i<shares; i++) {
            String s = "";
            // and every part of the secret...
            for (int j=0; j<secrets.size(); j++) {
                // generate a new x-coordinate
                BigInteger number = random();
                while (inNumbers(numbers, number)) {
                    number = random();
                }
                numbers.add(number);
                
                // and evaluate the polynomial at that point
                points[i][j][0] = number;
                points[i][j][1] = evaluatePolynomial(polynomial, j, number);
                
                // encode to Base64 or Hex.
                if (isBase64) {
                    s += toBase64(points[i][j][0]);
                    s += toBase64(points[i][j][1]);
                } else {
                    s += toHex(points[i][j][0]);
                    s += toHex(points[i][j][1]);
                }
                //System.out.println("x[share-"+i+"][part-"+j+"]: " + points[i][j][0].toString(10));
                //System.out.println("y[share-"+i+"][part-"+j+"]: " + points[i][j][1].toString(10));
            }
            rs.add(s);
        }
        
        return rs;
    }
    
    // Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm
    // Note: the polynomial will converge if the specified minimum number of shares
    //       or more are passed to this function. Passing thus does not affect it
    //       Passing fewer however, simply means that the returned secret is wrong.
    public String combine(List<String> shares, boolean isBase64) throws Exception {
        String rs = "";
        if (shares == null || shares.isEmpty()) {
            throw new Exception("shares is NULL or empty");
        }
        
        // Recreate the original object of x, y points, based upon number of shares
        // and size of each share (number of parts in the secret).
        // 
        // points[shares][parts][2]
        BigInteger[][][] points;
        if (isBase64) {
            points = decodeShareBase64(shares);
        } else {
            points = decodeShareHex(shares);
        }
        
        // Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
        // For each part of the secret (clearest to iterate over)...
        List<BigInteger> secrets = new ArrayList<>();
        int numSecret = points[0].length;
        for (int j=0; j<numSecret; j++) {
            secrets.add(BigInteger.ZERO);
            // and every share...
            for (int i=0; i<shares.size(); i++) { // LPI sum loop
                // remember the current x and y values
                BigInteger ax = points[i][j][0]; // ax
                BigInteger ay = points[i][j][1]; // ay
                BigInteger numerator = BigInteger.ONE; // LPI numerator
                BigInteger denominator = BigInteger.ONE; // LPI denominator
                // ...and for every other point...
                for (int k=0; k<shares.size(); k++) { // LPI product loop
                    if (k != i) {
                        // combine them via half products
                        // x=0 ==> [(0-bx)/(ax-bx)] * ...
                        BigInteger bx = points[k][j][0]; // bx
                        BigInteger negbx = bx.multiply(new BigInteger("-1")); // (0-bx)
                        BigInteger axbx = ax.subtract(bx); // (ax-bx)
                        numerator = numerator.multiply(negbx).mod(PRIME); // (0-bx)*...
                        denominator = denominator.multiply(axbx).mod(PRIME); // (ax-bx)*...
                    }
                }
                
                // LPI product: x=0, y = ay * [(x-bx)/(ax-bx)] * ...
                // multiply together the points (ay)(numerator)(denominator)^-1 ...
                BigInteger fx = ay.multiply(numerator).mod(PRIME);
                fx = fx.multiply(denominator.modInverse(PRIME)).mod(PRIME);
                
                // LPI sum: s = fx + fx + ...
                BigInteger secret = secrets.get(j);
                secret = secret.add(fx).mod(PRIME);
                secrets.set(j, secret);
            }
        }
        
        // recover secret string.
        rs = mergeBigIntToString(secrets);
        return rs;
    }
    
    // Takes a string array of shares encoded in Base64 created via Shamir's
    // Algorithm; each string must be of equal length of a multiple of 88 characters
    // as a single 88 character share is a pair of 256-bit numbers (x, y).
    public BigInteger[][][] decodeShareBase64(List<String> shares) throws Exception {
        // Recreate the original object of x, y points, based upon number of shares
        // and size of each share (number of parts in the secret).
        // 
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares.size()][][];
        
        // For each share...
        for (int i=0; i<shares.size(); i++) {
            // ensure that it is valid
            if (isValidShareBase64(shares.get(i)) == false) {
                throw new Exception("one of the shares is invalid");
            }
            
            // find the number of parts it represents.
            String share = shares.get(i);
            int count = share.length() / 88;
            points[i] = new BigInteger[count][];
            
            // and for each part, find the x,y pair...
            for (int j=0; j<count; j++) {
                points[i][j] = new BigInteger[2];
                String cshare = share.substring(j*88, (j+1)*88);
                // decoding from Base64.
                points[i][j][0] = fromBase64(cshare.substring(0, 44));
                points[i][j][1] = fromBase64(cshare.substring(44, 88));
            }
        }
        return points;
    }
    
    // Takes a string array of shares encoded in Hex created via Shamir's
    // Algorithm; each string must be of equal length of a multiple of 128 characters
    // as a single 128 character share is a pair of 256-bit numbers (x, y).
    public BigInteger[][][] decodeShareHex(List<String> shares) throws Exception {
        // Recreate the original object of x, y points, based upon number of shares
        // and size of each share (number of parts in the secret).
        // 
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares.size()][][];
        
        // For each share...
        for (int i=0; i<shares.size(); i++) {
            // ensure that it is valid
            if (isValidShareHex(shares.get(i)) == false) {
                throw new Exception("one of the shares is invalid");
            }
            
            // find the number of parts it represents.
            String share = shares.get(i);
            int count = share.length() / 128;
            points[i] = new BigInteger[count][];
            
            // and for each part, find the x,y pair...
            for (int j=0; j<count; j++) {
                points[i][j] = new BigInteger[2];
                String cshare = share.substring(j*128, (j+1)*128);
                // decoding from Hex.
                points[i][j][0] = fromHex(cshare.substring(0, 64));
                points[i][j][1] = fromHex(cshare.substring(64, 128));
            }
        }
        return points;
    }
    
    // https://www.baeldung.com/java-byte-arrays-hex-strings
    public String encodeHexString(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    // https://www.baeldung.com/java-byte-arrays-hex-strings
    public byte[] decodeHexString(String hexString) {
        return DatatypeConverter.parseHexBinary(hexString);
    }
    
    // Converts a byte array into an a 256-bit BigInteger, arraied based upon size of
    // the input byte; all values are right-padded to length 256 bit, even if the most
    // significant bit is zero.
    public List<BigInteger> splitSecretToBigInt(String secret) {
        List<BigInteger> rs = new ArrayList<>();
        if (secret != null && !secret.isEmpty()) {
            byte[] sbyte = secret.getBytes(StandardCharsets.UTF_8);
            String hexData = encodeHexString(sbyte);
            int count = (int) Math.ceil(hexData.length() / 64.0);
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
    
    // Converts an array of BigInteger to the original byte array, removing any least significant nulls
    public String mergeBigIntToString(List<BigInteger> secrets) {
        String rs = "";
        String hexData = "";
        for (BigInteger s : secrets) {
            String tmp = s.toString(16);
            String pading = "";
            for (int j=0; j<(64-tmp.length()); j++) {
                pading += "0";
            }
            hexData = hexData + pading + tmp;
        }
        byte[] byteData = decodeHexString(hexData);
        byteData = trimRight(byteData);
        //System.out.println("byteData: " + Arrays.toString(byteData));
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
        return accum;
    }
    
    // https://www.baeldung.com/java-base64-encode-and-decode
    // Return Base64 string from BigInteger 256 bits long
    public String toBase64(BigInteger number) {
        String hexdata = number.toString(16);
        int n = 64 - hexdata.length();
        for (int i=0; i<n; i++) {
            hexdata = "0" + hexdata;
        }
        return Base64.getUrlEncoder().encodeToString(decodeHexString(hexdata));
    }
    
    // Return Hex string from BigInteger 256 bits long
    public String toHex(BigInteger number) {
        String hexdata = number.toString(16);
        int n = 64 - hexdata.length();
        for (int i=0; i<n; i++) {
            hexdata = "0" + hexdata;
        }
        return hexdata;
    }
    
    // Return BigInteger from Base64 string.
    public BigInteger fromBase64(String number) {
        byte[] bytedata = Base64.getUrlDecoder().decode(number);
        String hexdata = encodeHexString(bytedata);
        return new BigInteger(hexdata, 16);
    }
    
    // Return BigInteger from Hex string.
    public BigInteger fromHex(String number) {
        return new BigInteger(number, 16);
    }
    
    // Takes in a given string to check if it is a valid secret
    // Requirements:
    // 	 Length multiple of 88
    //	 Can decode each 44 character block as Base64
    // Returns only success/failure (bool)
    public boolean isValidShareBase64(String candidate) throws Exception {
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
    
    // Takes in a given string to check if it is a valid secret
    // Requirements:
    // 	 Length multiple of 128
    //	 Can decode each 64 character block as Hex
    // Returns only success/failure (bool)
    public boolean isValidShareHex(String candidate) throws Exception {
        if (candidate == null || candidate.isEmpty()) {
            throw new Exception("String is NULL or empty.");
        }
        if (candidate.length()%128 != 0) {
            return false;
        }
        int count = candidate.length() / 64;
        for (int i=0; i<count; i++) {
            String part = candidate.substring(i*64, (i+1)*64);
            BigInteger decode = fromHex(part);
            // decode < 0 || decode > PRIME ==> false
            if (decode.compareTo(BigInteger.ONE) == -1 || decode.compareTo(PRIME) == 1) {
                return false;
            }
        }
        return true;
    }
}
