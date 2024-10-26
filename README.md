# ntc-jcrypto
ntc-jcrypto is a module java cryptography  

## Maven
```Xml
<!-- Java 8 -->
<dependency>
    <groupId>com.streetcodevn</groupId>
    <artifactId>ntc-jcrypto</artifactId>
    <version>1.0.2</version>
</dependency>

<!-- Java 11 -->
<dependency>
    <groupId>com.streetcodevn</groupId>
    <artifactId>ntc-jcrypto</artifactId>
    <version>2.0.0</version>
</dependency>
```

## 1. An implementation of Shamir's Secret Sharing Algorithm 256-bits in Java

### Usage
**Use encode/decode Base64**  
```java
String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
SSS sss = new SSS();
List<String> arr = sss.create(3, 6, s, true);
//System.out.println(arr);
for (int i=0; i<arr.size(); i++) {
    System.out.println("shares["+i+"]: " + arr.get(i));
}

System.out.println("\nsecret: " + s);
System.out.println("secret.length: " + s.length());

String s1 = sss.combine(arr.subList(0, 3), true);
System.out.println("combines shares 1 length = " + arr.subList(0, 3).size());
System.out.println("secret: " + s1);
System.out.println("secret.length: " + s1.length());

String s2 = sss.combine(arr.subList(3, 6), true);
System.out.println("combines shares 2 length = " + arr.subList(3, 6).size());
System.out.println("secret: " + s2);
System.out.println("secret.length: " + s2.length());

String s3 = sss.combine(arr.subList(1, 5), true);
System.out.println("combines shares 3 length = " + arr.subList(1, 5).size());
System.out.println("secret: " + s3);
System.out.println("secret.length: " + s3.length());
```

**Use encode/decode Hex**  
```java
String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
SSS sss = new SSS();
List<String> arr = sss.create(3, 6, s, false);
//System.out.println(arr);
for (int i=0; i<arr.size(); i++) {
    System.out.println("shares["+i+"]: " + arr.get(i));
}

System.out.println("\nsecret: " + s);
System.out.println("secret.length: " + s.length());

String s1 = sss.combine(arr.subList(0, 3), false);
System.out.println("combines shares 1 length = " + arr.subList(0, 3).size());
System.out.println("secret: " + s1);
System.out.println("secret.length: " + s1.length());

String s2 = sss.combine(arr.subList(3, 6), false);
System.out.println("combines shares 2 length = " + arr.subList(3, 6).size());
System.out.println("secret: " + s2);
System.out.println("secret.length: " + s2.length());

String s3 = sss.combine(arr.subList(1, 5), false);
System.out.println("combines shares 3 length = " + arr.subList(1, 5).size());
System.out.println("secret: " + s3);
System.out.println("secret.length: " + s3.length());
```

## License
This code is under the [Apache License v2](https://www.apache.org/licenses/LICENSE-2.0).  
