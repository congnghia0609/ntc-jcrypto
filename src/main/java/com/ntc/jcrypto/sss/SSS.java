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
//import javax.xml.bind.DatatypeConverter;
import jakarta.xml.bind.DatatypeConverter;

/**
 *
 * @author nghiatc
 * @since Jan 3, 2020
 */
public class SSS {

    // https://primes.utm.edu/lists/2small/200bit.html
    // PRIME = 2^n - k = 2^256 - 189
    private static final BigInteger PRIME = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639747");
    private Random rand = new SecureRandom();

    /**
     * Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings) created by Shamir's Secret
     * Sharing Algorithm requiring a minimum number of share to recreate, of length shares, from the input secret raw as
     * a string
     *
     * @param minimum int minimum
     * @param shares int shares
     * @param secret String secret
     * @param isBase64 True using encode Base64Url, otherwise encode Hex
     * @return List string shares
     * @throws Exception Input params invalid
     */
    public List<String> create(int minimum, int shares, String secret, boolean isBase64) throws Exception {
        List<String> rs = new ArrayList<>();
        // Verify minimum isn't greater than shares; there is no way to recreate
        // the original polynomial in our current setup, therefore it doesn't make
        // sense to generate fewer shares than are needed to reconstruct the secret.
        if (minimum <= 0 || shares <= 0) {
            throw new Exception("minimum or shares is invalid");
        }
        if (minimum > shares) {
            throw new Exception("cannot require more shares then existing");
        }
        if (secret == null || secret.isEmpty()) {
            throw new Exception("secret is NULL or empty");
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
        for (int i = 0; i < secrets.size(); i++) {
            polynomial[i][0] = secrets.get(i);
            for (int j = 1; j < minimum; j++) {
                // Each coefficient should be unique
                BigInteger number = random();
                while (inNumbers(numbers, number)) {
                    number = random();
                }
                numbers.add(number);

                polynomial[i][j] = number;
            }
        }

        // Create the points object; this holds the (x, y) points of each share.
        // Again, because secrets is an array, each share could have multiple parts
        // over which we are computing Shamir's Algorithm. The last dimension is
        // always two, as it is storing an x, y pair of points.
        // 
        // For every share...
        for (int i = 0; i < shares; i++) {
            String s = "";
            // and every part of the secret...
            for (int j = 0; j < secrets.size(); j++) {
                // generate a new x-coordinate
                BigInteger x = random();
                while (inNumbers(numbers, x)) {
                    x = random();
                }
                numbers.add(x);

                // and evaluate the polynomial at that point
                BigInteger y = evaluatePolynomial(polynomial, j, x);

                // encode to Base64 or Hex.
                if (isBase64) {
                    s += toBase64(x);
                    s += toBase64(y);
                } else {
                    s += toHex(x);
                    s += toHex(y);
                }
            }
            rs.add(s);
        }

        return rs;
    }

    /**
     * Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm Note: the polynomial will
     * converge if the specified minimum number of shares or more are passed to this function. Passing thus does not
     * affect it Passing fewer however, simply means that the returned secret is wrong.
     *
     * @param shares List string shares
     * @param isBase64 True using decode Base64Url, otherwise decode Hex
     * @return String secret
     * @throws Exception Input params invalid
     */
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
        for (int j = 0; j < numSecret; j++) {
            secrets.add(BigInteger.ZERO);
            // and every share...
            for (int i = 0; i < shares.size(); i++) { // LPI sum loop
                // remember the current x and y values
                BigInteger ax = points[i][j][0]; // ax
                BigInteger ay = points[i][j][1]; // ay
                BigInteger numerator = BigInteger.ONE; // LPI numerator
                BigInteger denominator = BigInteger.ONE; // LPI denominator
                // and for every other point...
                for (int k = 0; k < shares.size(); k++) { // LPI product loop
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

    /**
     * Takes a string array of shares encoded in Base64 created via Shamir's Algorithm; each string must be of equal
     * length of a multiple of 88 characters as a single 88 character share is a pair of 256-bit numbers (x, y).
     *
     * @param shares List string shares
     * @return BigInteger[][][] Matrix points
     * @throws Exception Input params invalid
     */
    public BigInteger[][][] decodeShareBase64(List<String> shares) throws Exception {
        // Recreate the original object of x, y points, based upon number of shares
        // and size of each share (number of parts in the secret).
        // 
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares.size()][][];

        // For each share...
        for (int i = 0; i < shares.size(); i++) {
            // ensure that it is valid
            if (isValidShareBase64(shares.get(i)) == false) {
                throw new Exception("one of the shares is invalid");
            }

            // find the number of parts it represents.
            String share = shares.get(i);
            int count = share.length() / 88;
            points[i] = new BigInteger[count][];

            // and for each part, find the x,y pair...
            for (int j = 0; j < count; j++) {
                points[i][j] = new BigInteger[2];
                String cshare = share.substring(j * 88, (j + 1) * 88);
                // decoding from Base64.
                points[i][j][0] = fromBase64(cshare.substring(0, 44));
                points[i][j][1] = fromBase64(cshare.substring(44, 88));
            }
        }
        return points;
    }

    /**
     * Takes a string array of shares encoded in Hex created via Shamir's Algorithm; each string must be of equal length
     * of a multiple of 128 characters as a single 128 character share is a pair of 256-bit numbers (x, y).
     *
     * @param shares List string shares
     * @return BigInteger[][][] Matrix points
     * @throws Exception Input params invalid
     */
    public BigInteger[][][] decodeShareHex(List<String> shares) throws Exception {
        // Recreate the original object of x, y points, based upon number of shares
        // and size of each share (number of parts in the secret).
        // 
        // points[shares][parts][2]
        BigInteger[][][] points = new BigInteger[shares.size()][][];

        // For each share...
        for (int i = 0; i < shares.size(); i++) {
            // ensure that it is valid
            if (isValidShareHex(shares.get(i)) == false) {
                throw new Exception("one of the shares is invalid");
            }

            // find the number of parts it represents.
            String share = shares.get(i);
            int count = share.length() / 128;
            points[i] = new BigInteger[count][];

            // and for each part, find the x,y pair...
            for (int j = 0; j < count; j++) {
                points[i][j] = new BigInteger[2];
                String cshare = share.substring(j * 128, (j + 1) * 128);
                // decoding from Hex.
                points[i][j][0] = fromHex(cshare.substring(0, 64));
                points[i][j][1] = fromHex(cshare.substring(64, 128));
            }
        }
        return points;
    }

    // Convert ByteArrays to Hex String
    public String encodeHexString(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

    // Convert Hex String to ByteArrays
    public byte[] decodeHexString(String hexString) {
        return DatatypeConverter.parseHexBinary(hexString);
    }

    // Converts a byte array into an a 256-bit BigInteger, array based upon size of
    // the input byte; all values are right-padded to length 256 bit, even if the most
    // significant bit is zero.
    public List<BigInteger> splitSecretToBigInt(String secret) {
        List<BigInteger> rs = new ArrayList<>();
        if (secret != null && !secret.isEmpty()) {
            byte[] sbyte = secret.getBytes(StandardCharsets.UTF_8);
            String hexData = encodeHexString(sbyte);
            int count = (int) Math.ceil(hexData.length() / 64.0);
            for (int i = 0; i < count; i++) {
                if ((i + 1) * 64 < hexData.length()) {
                    BigInteger bi = new BigInteger(hexData.substring(i * 64, (i + 1) * 64), 16);
                    rs.add(bi);
                } else {
                    String last = hexData.substring(i * 64, hexData.length());
                    int n = 64 - last.length();
                    for (int j = 0; j < n; j++) {
                        last += "0";
                    }
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
            int n = 64 - tmp.length();
            for (int j = 0; j < n; j++) {
                tmp = "0" + tmp;
            }
            hexData = hexData + tmp;
        }
        byte[] byteData = decodeHexString(hexData);
        byteData = trimRight(byteData);
        rs = new String(byteData, StandardCharsets.UTF_8);
        return rs;
    }

    // Remove right padding null bytes
    public byte[] trimRight(byte[] bytes) {
        int end = bytes.length;
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            end = i;
            --i;
        }
        return end == bytes.length ? bytes : Arrays.copyOf(bytes, end);
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
    // y = a + bx + cx^2 + dx^3 = ((dx + c)x + b)x + a
    private BigInteger evaluatePolynomial(BigInteger[][] poly, int part, BigInteger x) {
        int last = poly[part].length - 1;
        BigInteger accum = poly[part][last];
        for (int i = last - 1; i >= 0; --i) {
            accum = accum.multiply(x).add(poly[part][i]).mod(PRIME);
        }
        return accum;
    }

    // Return Base64 string from BigInteger 256 bits long
    public String toBase64(BigInteger number) {
        String hexdata = number.toString(16);
        int n = 64 - hexdata.length();
        for (int i = 0; i < n; i++) {
            hexdata = "0" + hexdata;
        }
        return Base64.getUrlEncoder().encodeToString(decodeHexString(hexdata));
    }

    // Return Hex string from BigInteger 256 bits long
    public String toHex(BigInteger number) {
        String hexdata = number.toString(16);
        int n = 64 - hexdata.length();
        for (int i = 0; i < n; i++) {
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
            return false;
        }
        if (candidate.length() % 88 != 0) {
            return false;
        }
        int count = candidate.length() / 44;
        for (int i = 0; i < count; i++) {
            String part = candidate.substring(i * 44, (i + 1) * 44);
            BigInteger decode = fromBase64(part);
            // decode <= 0 || decode >= PRIME ==> false
            if (decode.compareTo(BigInteger.ZERO) <= 0 || decode.compareTo(PRIME) >= 0) {
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
            return false;
        }
        if (candidate.length() % 128 != 0) {
            return false;
        }
        int count = candidate.length() / 64;
        for (int i = 0; i < count; i++) {
            String part = candidate.substring(i * 64, (i + 1) * 64);
            BigInteger decode = fromHex(part);
            // decode <= 0 || decode >= PRIME ==> false
            if (decode.compareTo(BigInteger.ZERO) <= 0 || decode.compareTo(PRIME) >= 0) {
                return false;
            }
        }
        return true;
    }
}
